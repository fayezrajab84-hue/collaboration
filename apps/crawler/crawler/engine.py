"""
Crawl engine.

Breadth-first crawl driven by Playwright Chromium. Captures:
  - navigation URLs (discovered_urls, source="link"/"seed")
  - observed XHR/fetch calls (api_endpoints)
  - SPA router routes (source="spa-router") when present
  - form submissions (source="form") when ``interact_with_forms`` is set
  - OpenAPI-declared endpoints (source="openapi") when ``openapi_spec_url`` is set

Phases delivered here:
  Phase 1 — BFS + link + XHR observation
  Phase 2 — authentication (form / header / cookie / oauth2)
  Phase 3 — form walks, SPA routing, OpenAPI pre-seeding

Runs entirely in-process inside the crawler container; no persistent state.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    async_playwright,
)

from config import CONFIG
from models import (
    CrawlRequest,
    CrawlResult,
    CrawlStats,
    DiscoveredUrl,
    StopReason,
    XhrCall,
)

from .auth import apply_auth
from .dedupe import in_scope, normalize_url
from .forms import walk_forms
from .openapi import fetch_and_extract_urls
from .progress import ProgressReporter
from .spa import discover_spa_routes

log = logging.getLogger("crawler.engine")


# ── Internal task shape ────────────────────────────────────────────────────

@dataclass
class _Task:
    url: str
    depth: int
    source: str


# ── Public entrypoint ──────────────────────────────────────────────────────

async def crawl(req: CrawlRequest) -> CrawlResult:
    """Run a single crawl end-to-end and return the aggregated result."""
    # Resolve limits — request overrides default, both capped by hard ceilings.
    max_pages = min(
        req.max_pages or CONFIG.default_max_pages,
        CONFIG.hard_max_pages,
    )
    max_depth = min(
        req.max_depth if req.max_depth is not None else CONFIG.default_max_depth,
        CONFIG.hard_max_depth,
    )
    max_duration_secs = min(
        req.max_duration_secs or CONFIG.default_max_duration_secs,
        CONFIG.hard_max_duration_secs,
    )

    origin_host = urlparse(str(req.target_url)).netloc
    started = time.monotonic()
    deadline = started + max_duration_secs

    discovered: list[DiscoveredUrl] = []
    xhr_observed: list[XhrCall] = []
    warnings: list[str] = []
    visited: set[str] = set()
    queue: deque[_Task] = deque()
    queue.append(_Task(url=str(req.target_url), depth=0, source="seed"))

    stop_reason: StopReason = "complete"
    auth_success: Optional[bool] = None
    auth_evidence: Optional[str] = None
    forms_found_count = 0
    # (action, method, field_names) tuples — prevents the same form being
    # submitted twice even if reached via two paths.
    submitted_forms: set[tuple[str, str, tuple[str, ...]]] = set()

    reporter = ProgressReporter(
        callback_url=req.progress_callback_url,
        run_id=req.run_id,
        throttle_secs=req.progress_throttle_secs,
    )

    async with async_playwright() as pw, reporter:
        browser = await _launch_browser(pw, req)
        try:
            context = await _new_context(browser, req)
            page = await context.new_page()

            # Attach request-level observer — captures XHR/fetch URLs and
            # navigations the browser itself emits (not just our goto calls).
            page.on(
                "request",
                lambda r: _on_request(r, xhr_observed, discovered, origin_host, req),
            )

            # Authenticate before the BFS starts so session cookies / bearer
            # tokens / injected headers apply to every subsequent request.
            if req.auth is not None:
                result = await apply_auth(context, page, req.auth)
                auth_success = result.success
                auth_evidence = result.evidence
                if not result.success:
                    warnings.append(f"auth failed: {result.evidence}")
                    # Continue anyway — an unauth crawl is still signal for DAST.
                    log.warning("auth failed, continuing unauthenticated: %s", result.evidence)
                else:
                    log.info("auth succeeded: %s", result.evidence)

            # OpenAPI pre-seeding — every declared path becomes a BFS seed,
            # so the crawl sees endpoints even if nothing links to them.
            if req.openapi_spec_url:
                proxy = (
                    CONFIG.zap_proxy_url
                    if req.use_zap_proxy and CONFIG.zap_proxy_url
                    else None
                )
                gets, others = await fetch_and_extract_urls(
                    req.openapi_spec_url, str(req.target_url), proxy=proxy
                )
                for url in gets:
                    if in_scope(url, origin_host, req.include_paths, req.exclude_paths):
                        queue.append(_Task(url=url, depth=0, source="openapi"))
                # Non-GET methods are recorded but not auto-visited.
                for url in others:
                    discovered.append(
                        DiscoveredUrl(
                            url=url,
                            method="NON_GET",
                            depth=-1,
                            source="openapi",
                        )
                    )
                if gets or others:
                    log.info(
                        "openapi seeded %d GET and %d non-GET endpoints",
                        len(gets), len(others),
                    )

            while queue:
                if len(visited) >= max_pages:
                    stop_reason = "max_pages"
                    break
                if time.monotonic() >= deadline:
                    stop_reason = "max_duration"
                    break

                task = queue.popleft()
                norm = normalize_url(task.url)
                if norm in visited:
                    continue
                if not in_scope(task.url, origin_host, req.include_paths, req.exclude_paths):
                    continue
                visited.add(norm)

                nav = await _visit(page, task, max_depth, queue, req)
                discovered.append(nav)

                # Emit progress (throttled internally).
                await reporter.emit(
                    pages_visited=len(visited),
                    pages_queued=len(queue),
                    xhr_observed=len(xhr_observed),
                    forms_found=forms_found_count,
                    current_url=task.url,
                )

                # Only explore SPA routes + forms on pages that actually loaded.
                if nav.error is not None:
                    continue

                # SPA routing: derive hash/data-attr routes and enqueue.
                if task.depth < max_depth:
                    try:
                        spa_urls = await discover_spa_routes(page, task.url)
                    except Exception as exc:
                        log.debug("spa discovery failed on %s: %s", task.url, exc)
                        spa_urls = []
                    for u in spa_urls:
                        queue.append(_Task(url=u, depth=task.depth + 1, source="spa-router"))

                # Form walks — off by default, enabled with `interact_with_forms`.
                if req.interact_with_forms:
                    try:
                        form_records = await walk_forms(
                            page, task.url, origin_host, submitted_forms
                        )
                    except Exception as exc:
                        log.debug("form walk failed on %s: %s", task.url, exc)
                        form_records = []
                    for fr in form_records:
                        forms_found_count += 1
                        if fr.skipped_reason is None:
                            # The submit may have navigated the page elsewhere;
                            # record the action URL as a form-sourced discovery.
                            discovered.append(
                                DiscoveredUrl(
                                    url=fr.action,
                                    method=fr.method,
                                    depth=task.depth + 1,
                                    source="form",
                                )
                            )

            # Final event so the dashboard can flip to "crawl done" immediately
            # instead of waiting for the next scheduled throttle tick.
            await reporter.emit(
                pages_visited=len(visited),
                pages_queued=len(queue),
                xhr_observed=len(xhr_observed),
                forms_found=forms_found_count,
                current_url=None,
                force=True,
            )
            await context.close()
        finally:
            await browser.close()

    duration = time.monotonic() - started
    return CrawlResult(
        discovered_urls=discovered,
        api_endpoints=_dedupe_xhr(xhr_observed),
        auth_success=auth_success,
        auth_evidence=auth_evidence,
        stats=CrawlStats(
            pages_visited=len(visited),
            forms_found=forms_found_count,
            xhr_observed=len(xhr_observed),
            duration_secs=round(duration, 2),
            stopped_reason=stop_reason,
        ),
        warnings=warnings,
    )


# ── Browser bring-up ───────────────────────────────────────────────────────

async def _launch_browser(pw, req: CrawlRequest) -> Browser:
    launch_kwargs: dict = {
        "headless": CONFIG.headless,
        # Chromium rejects ZAP's self-signed MITM cert without these flags.
        "args": ["--ignore-certificate-errors", "--no-sandbox"],
    }
    if req.use_zap_proxy and CONFIG.zap_proxy_url:
        launch_kwargs["proxy"] = {"server": CONFIG.zap_proxy_url}
    return await pw.chromium.launch(**launch_kwargs)


async def _new_context(browser: Browser, req: CrawlRequest) -> BrowserContext:
    extra_headers: dict[str, str] = {}
    if req.run_id:
        # Lets downstream scanners attribute observed traffic to this run.
        extra_headers["X-Crawler-Run-Id"] = req.run_id
    return await browser.new_context(
        viewport={
            "width": CONFIG.viewport_width,
            "height": CONFIG.viewport_height,
        },
        ignore_https_errors=CONFIG.ignore_https_errors,
        extra_http_headers=extra_headers or None,
    )


# ── Per-page visit ─────────────────────────────────────────────────────────

async def _visit(
    page: Page,
    task: _Task,
    max_depth: int,
    queue: deque[_Task],
    req: CrawlRequest,
) -> DiscoveredUrl:
    """Navigate to ``task.url`` and enqueue discovered links."""
    # Strategy: wait for DOM first (fast, reliable), then try for networkidle
    # with a short budget so SPAs that keep long-polling don't stall the crawl.
    try:
        response = await page.goto(
            task.url,
            wait_until="domcontentloaded",
            timeout=CONFIG.default_page_timeout_ms,
        )
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass  # networkidle is best-effort; DOM is already ready
    except Exception as exc:  # Playwright raises a family of exceptions here
        log.warning("goto failed: %s — %s", task.url, exc)
        return DiscoveredUrl(
            url=task.url,
            depth=task.depth,
            source=task.source,  # type: ignore[arg-type]
            error=str(exc).splitlines()[0][:200],
        )

    status = response.status if response else None
    content_type = (
        response.headers.get("content-type") if response and response.headers else None
    )

    # Enqueue in-scope links for further crawling, respecting depth.
    if task.depth < max_depth:
        links = await _extract_links(page, task.url)
        for href in links:
            queue.append(_Task(url=href, depth=task.depth + 1, source="link"))

    return DiscoveredUrl(
        url=task.url,
        depth=task.depth,
        source=task.source,  # type: ignore[arg-type]
        status=status,
        content_type=content_type,
    )


async def _extract_links(page: Page, base_url: str) -> list[str]:
    """Read every <a href> on the page and resolve it against ``base_url``."""
    try:
        raw_hrefs: list[Optional[str]] = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(e => e.getAttribute('href'))",
        )
    except Exception as exc:
        log.debug("link extraction failed on %s: %s", base_url, exc)
        return []

    absolute: list[str] = []
    for href in raw_hrefs:
        if not href:
            continue
        href = href.strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        try:
            absolute.append(urljoin(base_url, href))
        except ValueError:
            continue
    return absolute


# ── Network observation ────────────────────────────────────────────────────

def _on_request(
    request: Request,
    xhr_out: list[XhrCall],
    discovered_out: list[DiscoveredUrl],
    origin_host: str,
    req: CrawlRequest,
) -> None:
    """
    Capture every request the browser emits.

    Playwright's ``resource_type`` is "xhr" / "fetch" for API-style calls,
    "document" for top-level nav, "script"/"stylesheet"/"image" for assets.

    We keep xhr/fetch (valuable API surface) and drop static assets.
    """
    try:
        rtype = request.resource_type
        url = request.url
        if rtype in ("xhr", "fetch"):
            # Only care about same-origin API calls — third-party analytics
            # are noise and often out of scope for DAST. Compare parsed
            # netloc so third-party URLs that *contain* the origin host in
            # a query param (e.g. GA's `?dl=https%3A%2F%2F<origin>%2F`)
            # aren't mistaken for same-origin traffic.
            if urlparse(url).netloc == origin_host:
                xhr_out.append(
                    XhrCall(
                        url=url,
                        method=request.method,
                        content_type=(request.headers or {}).get("content-type"),
                    )
                )
                discovered_out.append(
                    DiscoveredUrl(
                        url=url,
                        method=request.method,
                        depth=-1,  # observed, not crawled
                        source="xhr",
                    )
                )
    except Exception:
        # Observer must never crash the crawl.
        pass


def _dedupe_xhr(calls: list[XhrCall]) -> list[XhrCall]:
    """Collapse duplicate (method, normalized_url) pairs."""
    seen: set[tuple[str, str]] = set()
    out: list[XhrCall] = []
    for c in calls:
        key = (c.method, normalize_url(c.url))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# Silence asyncio "Event loop is closed" noise on shutdown — it's harmless
# but clutters logs when the sidecar restarts.
def _configure_shutdown() -> None:
    logging.getLogger("asyncio").setLevel(logging.ERROR)


_configure_shutdown()


# Exported for tests.
__all__ = ["crawl"]
