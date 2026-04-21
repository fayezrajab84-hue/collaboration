"""
Phase 3 SPA router heuristics.

Single-page apps route client-side via ``history.pushState``/hash changes —
the browser never actually navigates, so our ``<a href>`` link extractor
doesn't see those routes. Popular frameworks (React Router, Vue Router,
Angular Router) expose clickable elements that mutate the URL without a
full reload.

This module scrapes candidate router elements and returns their *derived*
URLs so the BFS queue can enqueue them. We do NOT click them — clicking
has side effects (opens modals, triggers XHR, plays autoplay video); it's
safer to compute the target URL from attributes and let the regular BFS
navigate to it.

Heuristics (ordered by confidence):

1. ``<a href="/...">`` with a ``router-link`` / ``data-router`` style
   marker — already caught by the Phase 1 link extractor, so no-op here.
2. ``<a href="#/path">`` — hash routing (older React/Vue).
3. Any element with ``data-href`` / ``data-url`` / ``data-route`` attrs.
4. ``<Link to="...">``-style rendered output usually lands in ``href``,
   already covered by (1).

Future work (explicitly out of scope here): actually clicking buttons that
mutate state and observing the resulting XHR. That requires a
stateful walk + rollback strategy.
"""
from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urljoin

from playwright.async_api import Page

log = logging.getLogger("crawler.spa")


# Attributes commonly used by SPAs to encode a route on non-<a> elements.
_ROUTE_ATTRS = ("data-href", "data-url", "data-route", "data-to")


async def discover_spa_routes(page: Page, page_url: str) -> list[str]:
    """Return a list of absolute URLs derived from SPA routing markers."""
    found: set[str] = set()

    # Hash-routed <a> links — Phase 1 extractor filters `#`-only anchors, so
    # we explicitly re-scan for `#/...` which IS a route.
    try:
        hash_hrefs: list[Optional[str]] = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => e.getAttribute('href'))",
        )
        for h in hash_hrefs:
            if h and h.startswith("#/") and len(h) > 2:
                found.add(urljoin(page_url, h))
    except Exception as exc:
        log.debug("hash-link extraction failed: %s", exc)

    # Data-attribute routes.
    for attr in _ROUTE_ATTRS:
        try:
            vals: list[Optional[str]] = await page.eval_on_selector_all(
                f"[{attr}]",
                f"els => els.map(e => e.getAttribute('{attr}'))",
            )
        except Exception:
            continue
        for v in vals:
            if not v:
                continue
            v = v.strip()
            if v.startswith(("javascript:", "mailto:", "#")):
                continue
            try:
                found.add(urljoin(page_url, v))
            except ValueError:
                continue

    return sorted(found)


__all__ = ["discover_spa_routes"]
