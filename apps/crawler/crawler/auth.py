"""
Phase 2 authentication strategies.

Applied to a Playwright ``BrowserContext`` *before* the BFS begins so every
subsequent request is authenticated. Each strategy returns an ``AuthResult``
indicating whether the attempt succeeded and why.

Strategies:

- ``form``    → navigate to login URL, fill fields, submit, verify success
- ``header``  → attach static headers (bearer tokens, API keys) to every request
- ``cookie``  → inject a pre-built cookie jar
- ``oauth2``  → fetch a token via client-credentials flow, then apply as header

Design notes:

- ``form`` uses the same Playwright page the crawl will use. Session cookies
  issued by the server flow through the context naturally — no manual copying.
- ``header`` + ``oauth2`` set context-level ``extra_http_headers`` so every
  subsequent navigation and XHR carries them.
- ``cookie`` adds cookies via ``context.add_cookies`` — Playwright validates
  shape server-side and will raise if, e.g., ``domain`` is missing.
- Success detection is *explicit*: at least one of ``success_url_contains``,
  ``success_selector``, or ``success_text`` must be configured. A silent
  "looks ok" would hide credential failures for hours of scan time.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx
from playwright.async_api import BrowserContext, Page

from models import (
    AuthConfig,
    CookieAuth,
    FormAuth,
    HeaderAuth,
    OAuth2Auth,
)

log = logging.getLogger("crawler.auth")


@dataclass
class AuthResult:
    success: bool
    evidence: str  # human-readable; surfaced in CrawlResult.auth_evidence


async def apply_auth(
    context: BrowserContext,
    page: Page,
    auth: AuthConfig,
) -> AuthResult:
    """Dispatch to the right strategy. Never raises — always returns a result."""
    try:
        if isinstance(auth, FormAuth):
            return await _apply_form(page, auth)
        if isinstance(auth, HeaderAuth):
            return await _apply_header(context, auth)
        if isinstance(auth, CookieAuth):
            return await _apply_cookie(context, auth)
        if isinstance(auth, OAuth2Auth):
            return await _apply_oauth2(context, auth)
        return AuthResult(success=False, evidence=f"unknown auth type: {type(auth).__name__}")
    except Exception as exc:
        log.exception("auth strategy %s crashed", type(auth).__name__)
        return AuthResult(success=False, evidence=f"auth error: {exc}")


# ── FORM ───────────────────────────────────────────────────────────────────

async def _apply_form(page: Page, auth: FormAuth) -> AuthResult:
    if not any((auth.success_url_contains, auth.success_selector, auth.success_text)):
        return AuthResult(
            success=False,
            evidence="form auth requires at least one success_* indicator",
        )

    try:
        await page.goto(
            str(auth.login_url),
            wait_until="domcontentloaded",
            timeout=30000,
        )
    except Exception as exc:
        return AuthResult(success=False, evidence=f"login page load failed: {exc}")

    # Fill — .fill clears and types; preferred over .type() which would append.
    try:
        await page.fill(auth.username_selector, auth.username, timeout=5000)
        await page.fill(auth.password_selector, auth.password, timeout=5000)
    except Exception as exc:
        return AuthResult(success=False, evidence=f"filling credentials failed: {exc}")

    # Submit — click, then settle.
    #
    # We used to wrap this in ``page.expect_navigation``, but that approach is
    # fragile: on server-rendered forms (DVWA) the click's internal post-click
    # wait races against expect_navigation and times out even though the
    # navigation actually completes. Instead we:
    #
    #   1. Click with ``no_wait_after=True`` so Playwright does NOT auto-wait
    #      for post-click navigation (avoids the race entirely).
    #   2. Then ``wait_for_load_state`` ourselves — best-effort, so SPAs that
    #      never reach ``networkidle`` don't fail the whole auth.
    try:
        await page.click(auth.submit_selector, timeout=5000, no_wait_after=True)
    except Exception as exc:
        return AuthResult(success=False, evidence=f"submit click failed: {exc}")

    # Best-effort settle — both states are attempted, both failures ignored.
    for state in ("domcontentloaded", "networkidle"):
        try:
            await page.wait_for_load_state(state, timeout=10000)
        except Exception:
            pass

    # Verify — OR across configured indicators (any match = success).
    return await _verify_form_success(page, auth)


async def _verify_form_success(page: Page, auth: FormAuth) -> AuthResult:
    hits: list[str] = []

    if auth.success_url_contains:
        current = page.url
        if auth.success_url_contains in current:
            hits.append(f"url contains '{auth.success_url_contains}'")

    if auth.success_selector:
        try:
            el = await page.query_selector(auth.success_selector)
            if el is not None:
                hits.append(f"selector '{auth.success_selector}' found")
        except Exception:
            pass

    if auth.success_text:
        try:
            body = await page.content()
            if auth.success_text in body:
                hits.append(f"text '{auth.success_text}' present")
        except Exception:
            pass

    if hits:
        return AuthResult(success=True, evidence="; ".join(hits))
    return AuthResult(
        success=False,
        evidence=f"no success indicator matched (final url: {page.url})",
    )


# ── HEADER ─────────────────────────────────────────────────────────────────

async def _apply_header(context: BrowserContext, auth: HeaderAuth) -> AuthResult:
    if not auth.headers:
        return AuthResult(success=False, evidence="header auth: no headers provided")
    await context.set_extra_http_headers(auth.headers)
    redacted = ", ".join(_redact_header(k, v) for k, v in auth.headers.items())
    return AuthResult(success=True, evidence=f"headers applied: {redacted}")


def _redact_header(name: str, value: str) -> str:
    """Never log full tokens — show name + length only."""
    return f"{name}=<{len(value)} chars>"


# ── COOKIE ─────────────────────────────────────────────────────────────────

async def _apply_cookie(context: BrowserContext, auth: CookieAuth) -> AuthResult:
    if not auth.cookies:
        return AuthResult(success=False, evidence="cookie auth: no cookies provided")

    playwright_cookies = [
        {
            "name": c.name,
            "value": c.value,
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
            "httpOnly": c.http_only,
        }
        for c in auth.cookies
    ]
    try:
        await context.add_cookies(playwright_cookies)
    except Exception as exc:
        return AuthResult(success=False, evidence=f"cookie injection failed: {exc}")

    names = ", ".join(c.name for c in auth.cookies)
    return AuthResult(
        success=True,
        evidence=f"{len(auth.cookies)} cookie(s) injected: {names}",
    )


# ── OAUTH2 ─────────────────────────────────────────────────────────────────

async def _apply_oauth2(context: BrowserContext, auth: OAuth2Auth) -> AuthResult:
    """Client-credentials grant — the crawler acts as a confidential client."""
    data = {
        "grant_type": "client_credentials",
        "client_id": auth.client_id,
        "client_secret": auth.client_secret,
    }
    if auth.scope:
        data["scope"] = auth.scope
    if auth.audience:
        data["audience"] = auth.audience

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                str(auth.token_url),
                data=data,
                headers={"Accept": "application/json", **auth.extra_headers},
            )
    except Exception as exc:
        return AuthResult(success=False, evidence=f"token request failed: {exc}")

    if resp.status_code >= 400:
        return AuthResult(
            success=False,
            evidence=f"token endpoint returned {resp.status_code}",
        )

    try:
        token = resp.json().get("access_token")
    except Exception:
        return AuthResult(success=False, evidence="token response was not JSON")

    if not token or not isinstance(token, str):
        return AuthResult(success=False, evidence="no access_token in token response")

    await context.set_extra_http_headers({"Authorization": f"Bearer {token}"})
    return AuthResult(
        success=True,
        evidence=f"oauth2 token acquired (bearer, {len(token)} chars)",
    )


__all__ = ["apply_auth", "AuthResult"]
