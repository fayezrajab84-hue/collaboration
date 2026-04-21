"""
End-to-end safety + discovery test against the VulnSPA fixture.

Asserts the entire Phase 3 contract in a single crawl:

  * hash routes (``#/dashboard``) are enqueued via spa-router discovery
  * ``data-href`` / ``data-route`` targets are enqueued via spa-router discovery
  * GET and POST XHRs are recorded in ``api_endpoints`` (fetch observer)
  * Safe GET ``<form action="/search">`` IS submitted
  * Password form is SKIPPED
  * "Delete account" (destructive text) form is SKIPPED
  * ``card_number`` (forbidden field name) form is SKIPPED
  * ``javascript:`` / ``mailto:`` / cross-origin links are NEVER enqueued

Runs offline against the session-scoped conftest HTTP server.
"""
from __future__ import annotations

import pytest

from crawler.engine import crawl
from models import CrawlRequest


pytestmark = pytest.mark.asyncio


async def _run(target_url: str):
    return await crawl(
        CrawlRequest(
            target_url=target_url,
            max_pages=20,
            max_depth=3,
            max_duration_secs=60,
            use_zap_proxy=False,       # offline — no ZAP available in unit runs
            interact_with_forms=True,
            run_id="vuln-spa-safety",
        )
    )


async def test_vulnspa_full_safety_contract(vulnspa_url: str) -> None:
    result = await _run(vulnspa_url)

    urls = [d.url for d in result.discovered_urls]
    sources = {d.source for d in result.discovered_urls}
    xhr_urls = {x.url for x in result.api_endpoints}

    # ── Discovery — SPA routes are enqueued ────────────────────────────────
    assert "spa-router" in sources, (
        f"No spa-router source in discovered_urls (got {sources}). "
        "Hash route / data-href extraction is broken."
    )
    # data-href settings + data-route profile + hash-route dashboard
    joined = " ".join(urls)
    assert "/settings.html" in joined, "data-href target not enqueued"
    assert "/profile.html"  in joined, "data-route target not enqueued"
    assert "#/dashboard"    in joined or any("dashboard" in u for u in urls), (
        "Hash route #/dashboard not enqueued"
    )

    # ── XHR observer ───────────────────────────────────────────────────────
    assert any(u.endswith("/api/ping") for u in xhr_urls), (
        f"GET /api/ping XHR not observed — {xhr_urls}"
    )
    assert any(u.endswith("/api/stats") for u in xhr_urls), (
        f"POST /api/stats XHR not observed — {xhr_urls}"
    )

    # ── Safe form IS submitted ─────────────────────────────────────────────
    form_submissions = [d for d in result.discovered_urls if d.source == "form"]
    assert any("/search" in d.url for d in form_submissions), (
        f"Safe GET /search form was not submitted — forms={form_submissions}"
    )

    # ── Dangerous forms are SKIPPED ────────────────────────────────────────
    submitted_targets = " ".join(d.url for d in form_submissions)
    assert "/login" not in submitted_targets, (
        "Password form was submitted — safety rail broken"
    )
    assert "/accounts/delete" not in submitted_targets, (
        "Destructive-text form was submitted — safety rail broken"
    )
    assert "/pay" not in submitted_targets, (
        "Forbidden field-name (card_number) form was submitted — safety rail broken"
    )

    # ── Filtered link types ────────────────────────────────────────────────
    assert not any(u.startswith("javascript:") for u in urls), "javascript: leaked"
    assert not any(u.startswith("mailto:")     for u in urls), "mailto: leaked"
    assert not any("example.com" in u for u in urls), "cross-origin link leaked"

    # ── Sanity stats ──────────────────────────────────────────────────────
    assert result.stats.pages_visited >= 1
    assert result.stats.forms_found   >= 1
    assert result.stats.xhr_observed  >= 2
