"""
Crawler service configuration.

All values are read from environment variables at startup. Defaults are
safe for local Docker Compose; production deployments should override
anything that touches the network or resource caps.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


@dataclass(frozen=True)
class Config:
    # ZAP proxy — routed through by Chromium so every request is observed by
    # ZAP for passive scanning. Leave empty to crawl without proxying.
    zap_proxy_url: str = os.environ.get("ZAP_PROXY_URL", "")

    # Hard safety caps — enforced regardless of per-request values.
    hard_max_pages: int = _int("CRAWLER_HARD_MAX_PAGES", 500)
    hard_max_depth: int = _int("CRAWLER_HARD_MAX_DEPTH", 10)
    hard_max_duration_secs: int = _int("CRAWLER_HARD_MAX_DURATION_SECS", 900)

    # Per-page defaults (overridable per request).
    default_max_pages: int = _int("CRAWLER_DEFAULT_MAX_PAGES", 200)
    default_max_depth: int = _int("CRAWLER_DEFAULT_MAX_DEPTH", 5)
    default_max_duration_secs: int = _int("CRAWLER_DEFAULT_MAX_DURATION_SECS", 600)
    # 30s is the sweet spot: ZAP proxy adds ~8s TLS/cert handshake latency on
    # first request, and real-world sites (WebGoat, juice-shop, WordPress) can
    # take 10-20s for initial DOMContentLoaded. Hard duration cap still wins.
    default_page_timeout_ms: int = _int("CRAWLER_PAGE_TIMEOUT_MS", 30000)

    # Chromium tuning.
    headless: bool = _bool("CRAWLER_HEADLESS", True)
    ignore_https_errors: bool = _bool("CRAWLER_IGNORE_HTTPS_ERRORS", True)
    viewport_width: int = _int("CRAWLER_VIEWPORT_WIDTH", 1440)
    viewport_height: int = _int("CRAWLER_VIEWPORT_HEIGHT", 900)

    # Logging.
    log_level: str = os.environ.get("LOG_LEVEL", "info").lower()


CONFIG = Config()
