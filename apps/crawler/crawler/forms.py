"""
Phase 3 form interaction walks.

Real apps hide surface behind forms — search boxes, filter panels, "add to
cart" POSTs, checkout wizards. Passive link-crawling misses all of it.

This module discovers every ``<form>`` on a rendered page and optionally
submits it with synthetic-but-plausible values. The resulting POST (and any
navigation it triggers) shows up to ZAP for passive scanning + lets later
active scanners target those endpoints.

Safety rails (non-negotiable — a crawler that auto-submits *anything* will
post spam, trigger "forgot password" emails, reset databases, etc.):

- Only submit forms when ``req.interact_with_forms`` is true
- Skip any form containing password / file / credit-card / TOTP inputs
- Skip forms whose submit button text matches destructive keywords
  (delete / pay / confirm / transfer / unsubscribe / buy / publish)
- Skip forms pointing at a different origin
- Submit a form at most once per (action, method, normalized-fields) key

Nothing here runs until Phase 3 flags enable it; Phase 1/2 crawls remain
byte-identical.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import ElementHandle, Page

log = logging.getLogger("crawler.forms")


# Types of inputs we refuse to touch — each one represents real-world risk.
_FORBIDDEN_INPUT_TYPES = {"password", "file", "hidden-totp"}
# Field-name regexes that hint at sensitive/regulated data.
_FORBIDDEN_NAME_PATTERNS = (
    re.compile(r"(?i)(card|credit|cvv|cvc|ssn|iban|routing|totp|otp|mfa|secret)"),
)
# Submit-button text that strongly suggests irreversible side effects.
_DESTRUCTIVE_TEXT = re.compile(
    r"(?i)\b("
    r"delete|remove|destroy|wipe|"
    r"pay|checkout|purchase|buy|order|subscribe|"
    r"confirm|transfer|withdraw|send money|"
    r"publish|share|"
    r"unsubscribe|close account|deactivate"
    r")\b"
)

# Synthetic values — boring enough to pass server validation, obvious enough
# to spot in logs. Never PII.
_FILL_BY_TYPE = {
    "email": "crawler-probe@example.test",
    "tel": "+15555550100",
    "url": "https://crawler.example.test",
    "number": "1",
    "date": "2024-01-01",
    "time": "12:00",
    "color": "#123456",
    "search": "test",
    "text": "test",
    "textarea": "test",
}


@dataclass
class DiscoveredForm:
    action: str            # absolute URL
    method: str            # GET / POST
    field_names: tuple[str, ...]
    skipped_reason: Optional[str] = None  # None when submitted


async def walk_forms(
    page: Page,
    page_url: str,
    origin_host: str,
    submitted_fingerprints: set[tuple[str, str, tuple[str, ...]]],
) -> list[DiscoveredForm]:
    """
    Enumerate forms on the current page; safely submit those that pass the
    gate. Returns a record per form (including skipped ones, with the reason).
    """
    out: list[DiscoveredForm] = []
    try:
        forms = await page.query_selector_all("form")
    except Exception as exc:
        log.debug("form enumeration failed on %s: %s", page_url, exc)
        return out

    for form in forms:
        record = await _inspect_form(form, page_url, origin_host)
        if record is None:
            continue

        fp = (record.action, record.method, record.field_names)
        if fp in submitted_fingerprints:
            record.skipped_reason = "duplicate (already submitted)"
            out.append(record)
            continue

        if record.skipped_reason is not None:
            out.append(record)
            continue

        submitted_fingerprints.add(fp)
        try:
            await _submit_form(page, form)
            # Let the resulting page settle so the request observer captures it.
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
        except Exception as exc:
            record.skipped_reason = f"submit error: {exc}"
        out.append(record)

    return out


async def _inspect_form(
    form: ElementHandle,
    page_url: str,
    origin_host: str,
) -> Optional[DiscoveredForm]:
    """Pull attributes + decide whether this form is safe to submit."""
    try:
        raw_action = (await form.get_attribute("action")) or ""
        raw_method = ((await form.get_attribute("method")) or "GET").upper()
    except Exception:
        return None

    action = urljoin(page_url, raw_action) if raw_action else page_url
    if not action.startswith(("http://", "https://")):
        return DiscoveredForm(action=action, method=raw_method, field_names=(), skipped_reason="non-http action")

    if urlparse(action).netloc and urlparse(action).netloc != origin_host:
        return DiscoveredForm(
            action=action, method=raw_method, field_names=(),
            skipped_reason="cross-origin action",
        )

    # Enumerate fields + look for forbidden types/names.
    field_names: list[str] = []
    forbidden: Optional[str] = None
    try:
        inputs = await form.query_selector_all("input, textarea, select")
    except Exception:
        inputs = []

    for inp in inputs:
        itype = ((await inp.get_attribute("type")) or "text").lower()
        iname = (await inp.get_attribute("name")) or ""
        if iname:
            field_names.append(iname)
        if itype in _FORBIDDEN_INPUT_TYPES:
            forbidden = f"forbidden input type: {itype}"
            break
        for pat in _FORBIDDEN_NAME_PATTERNS:
            if iname and pat.search(iname):
                forbidden = f"forbidden field name: {iname}"
                break
        if forbidden:
            break

    # Destructive submit button text?
    if forbidden is None:
        try:
            buttons = await form.query_selector_all(
                "button[type=submit], button:not([type]), input[type=submit], input[type=image]"
            )
            for btn in buttons:
                label = (
                    (await btn.get_attribute("value"))
                    or (await btn.inner_text() if hasattr(btn, "inner_text") else "")
                    or ""
                )
                if label and _DESTRUCTIVE_TEXT.search(label):
                    forbidden = f"destructive submit: {label.strip()[:40]}"
                    break
        except Exception:
            pass

    return DiscoveredForm(
        action=action,
        method=raw_method,
        field_names=tuple(field_names),
        skipped_reason=forbidden,
    )


async def _submit_form(page: Page, form: ElementHandle) -> None:
    """Fill every visible input with a synthetic value, then click submit."""
    inputs = await form.query_selector_all("input, textarea, select")
    for inp in inputs:
        try:
            tag = (await inp.evaluate("el => el.tagName")).lower()
            itype = ((await inp.get_attribute("type")) or "text").lower()

            if tag == "select":
                # Pick the second option if available (first is often "-- choose --").
                opts = await inp.query_selector_all("option")
                if len(opts) >= 2:
                    val = await opts[1].get_attribute("value")
                    if val is not None:
                        await inp.select_option(value=val)
                elif opts:
                    val = await opts[0].get_attribute("value")
                    if val is not None:
                        await inp.select_option(value=val)
                continue

            if itype in ("checkbox", "radio"):
                await inp.check()
                continue

            if itype in ("submit", "reset", "button", "image", "hidden"):
                continue

            fill_value = _FILL_BY_TYPE.get(itype, "test")
            if tag == "textarea":
                fill_value = _FILL_BY_TYPE["textarea"]
            await inp.fill(fill_value, timeout=2000)
        except Exception:
            # A single bad field shouldn't abort the whole walk.
            continue

    # Submit — use requestSubmit so native validation still runs; fall back
    # to form.submit() which is more permissive on older DOMs.
    try:
        await form.evaluate("f => (f.requestSubmit ? f.requestSubmit() : f.submit())")
    except Exception as exc:
        log.debug("form submit failed: %s", exc)


__all__ = ["walk_forms", "DiscoveredForm"]
