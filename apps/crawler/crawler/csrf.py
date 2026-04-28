"""
CSRF token extraction & injection.

Many SPAs and modern server-rendered apps protect non-GET API calls with a
CSRF token that is *not* submitted as a hidden form field — instead the
client reads it from one of two well-known sources and re-sends it on every
mutating request as an HTTP header:

  1. **HTML meta tag** — Rails / Laravel / Spring SPA pattern:
        <meta name="csrf-token" content="abc...">
     The frontend JS reads `document.querySelector('meta[name="csrf-token"]')`
     and adds `X-CSRF-Token: abc...` to every fetch/XHR.

  2. **Double-submit cookie** — Django / Express csurf / Angular pattern:
        Set-Cookie: XSRF-TOKEN=abc...
     The frontend JS reads the cookie value and echoes it as
     `X-XSRF-TOKEN: abc...` so the server can compare cookie ↔ header.

The browser does NOT do either of these automatically — it's app-level JS.
So when our headless crawler issues XHRs (or follow-up navigations the SPA
treats as XHR-equivalent), they get rejected with 403 / "invalid CSRF token"
unless we mirror the JS behaviour.

This module reads the configured source after each navigation and updates
the BrowserContext's extra_http_headers so subsequent requests carry the
token. It is no-op when no CSRF config is provided.

Re-extraction happens on every page nav (cheap, ~ms) because some apps
rotate tokens per request — re-reading is the safe default.
"""
from __future__ import annotations

import logging
from typing import Optional

from playwright.async_api import BrowserContext, Page

from models import CsrfConfig

log = logging.getLogger("crawler.csrf")


async def extract_token(page: Page, cfg: CsrfConfig) -> Optional[str]:
    """
    Read the CSRF token from the configured source.

    Returns the token string, or ``None`` if the source isn't present on
    this page (e.g. unauthenticated landing pages don't have the meta tag
    until the user logs in). Returning ``None`` is *not* an error — the
    caller leaves the previous token in place.
    """
    # Meta-tag source — most common in Rails / Laravel / .NET SPAs.
    if cfg.meta_selector:
        try:
            handle = await page.query_selector(cfg.meta_selector)
            if handle is not None:
                content = await handle.get_attribute("content")
                if content:
                    return content.strip()
        except Exception as exc:
            log.debug("meta-tag extraction failed (%s): %s", cfg.meta_selector, exc)

    # Cookie source — double-submit pattern. We read from the BrowserContext
    # rather than the page so HttpOnly cookies are visible (page.evaluate
    # can't see HttpOnly).
    if cfg.cookie_name:
        try:
            cookies = await page.context.cookies()
            for c in cookies:
                if c.get("name") == cfg.cookie_name:
                    val = c.get("value")
                    if val:
                        return str(val).strip()
        except Exception as exc:
            log.debug("cookie extraction failed (%s): %s", cfg.cookie_name, exc)

    return None


async def apply_token(
    context: BrowserContext,
    token: str,
    cfg: CsrfConfig,
    *,
    preserve: Optional[dict[str, str]] = None,
) -> None:
    """
    Set ``cfg.header_name: token`` as an extra HTTP header on the context.

    ``preserve`` lets callers pass headers from earlier auth steps (bearer
    tokens, run-id) that must continue to ride alongside the CSRF header —
    Playwright's ``set_extra_http_headers`` is a *replacement*, not a merge.
    """
    headers: dict[str, str] = dict(preserve or {})
    headers[cfg.header_name] = token
    try:
        await context.set_extra_http_headers(headers)
    except Exception as exc:
        log.warning("failed to inject CSRF header: %s", exc)


async def refresh_from_page(
    context: BrowserContext,
    page: Page,
    cfg: CsrfConfig,
    *,
    preserve: Optional[dict[str, str]] = None,
    last_token: Optional[str] = None,
) -> Optional[str]:
    """
    Convenience wrapper: extract from current page, apply if found, return
    the token (or the previous ``last_token`` if no new value was visible).

    Returns the *effective* current token so the caller can keep tracking
    it across pages without re-reading on every check.
    """
    token = await extract_token(page, cfg)
    if token is None:
        return last_token
    if token == last_token:
        return token  # no change; avoid the round-trip
    await apply_token(context, token, cfg, preserve=preserve)
    log.debug("csrf token refreshed (%d chars) -> header %s", len(token), cfg.header_name)
    return token


__all__ = ["extract_token", "apply_token", "refresh_from_page"]
