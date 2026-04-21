"""
Crawler sidecar — FastAPI entrypoint.

Endpoints:
  GET  /health       — liveness probe used by Docker healthcheck
  POST /crawl        — run a crawl, block until complete, return result
  GET  /config       — inspect effective (non-secret) config (debug aid)

Intentionally stateless: every request starts a fresh Playwright browser.
Keeps the service trivially horizontally scalable at the cost of some
startup latency (~1–2s per crawl). Pooling can come later if needed.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException

from config import CONFIG
from crawler import crawl
from models import CrawlRequest, CrawlResult

# ── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, CONFIG.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
)
log = logging.getLogger("crawler.main")

# ── App ────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DevSecOps Crawler",
    version="0.1.0",
    description="Playwright-based SPA crawler for DAST scans.",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
async def current_config() -> dict:
    # Redact the ZAP proxy URL's auth portion if present.
    return {
        "zap_proxy_configured": bool(CONFIG.zap_proxy_url),
        "hard_max_pages": CONFIG.hard_max_pages,
        "hard_max_depth": CONFIG.hard_max_depth,
        "hard_max_duration_secs": CONFIG.hard_max_duration_secs,
        "default_max_pages": CONFIG.default_max_pages,
        "default_max_depth": CONFIG.default_max_depth,
        "default_max_duration_secs": CONFIG.default_max_duration_secs,
        "headless": CONFIG.headless,
        "viewport": {
            "width": CONFIG.viewport_width,
            "height": CONFIG.viewport_height,
        },
    }


@app.post("/crawl", response_model=CrawlResult)
async def run_crawl(req: CrawlRequest) -> CrawlResult:
    log.info(
        "crawl start url=%s depth=%s pages=%s run_id=%s",
        req.target_url,
        req.max_depth,
        req.max_pages,
        req.run_id,
    )
    try:
        result = await crawl(req)
    except Exception as exc:
        log.exception("crawl failed for %s", req.target_url)
        raise HTTPException(status_code=500, detail=f"crawl failed: {exc}") from exc

    log.info(
        "crawl done url=%s pages=%s xhr=%s duration=%.1fs reason=%s",
        req.target_url,
        result.stats.pages_visited,
        result.stats.xhr_observed,
        result.stats.duration_secs,
        result.stats.stopped_reason,
    )
    return result
