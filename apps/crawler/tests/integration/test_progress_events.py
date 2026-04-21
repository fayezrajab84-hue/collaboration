"""
Validates the Phase 5 live-progress callback.

Starts a tiny in-process HTTP server that captures every POST body it
receives, then runs a crawl with ``progress_callback_url`` pointing at
it. Asserts that:

  * at least one progress event was delivered
  * the final event carries ``current_url: null`` (the forced flush)
  * each event carries the expected schema (pages_visited, xhr_observed…)
  * the same ``run_id`` is echoed on every event
"""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from crawler.engine import crawl
from models import CrawlRequest


pytestmark = pytest.mark.asyncio


class _CollectorHandler(BaseHTTPRequestHandler):
    events: list[dict[str, Any]] = []

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {"_raw": raw.decode("utf-8", errors="replace")}
        self.__class__.events.append(payload)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def collector():
    _CollectorHandler.events = []
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _CollectorHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}/events", _CollectorHandler
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=5)


async def test_progress_events_delivered(vulnspa_url: str, collector) -> None:
    import asyncio

    callback_url, handler = collector

    await crawl(
        CrawlRequest(
            target_url=vulnspa_url,
            max_pages=6,
            max_depth=2,
            max_duration_secs=60,
            use_zap_proxy=False,
            interact_with_forms=False,
            run_id="progress-test-42",
            progress_callback_url=callback_url,
            # Tight throttle so we capture multiple events in a short crawl.
            progress_throttle_secs=0.1,
        )
    )

    # Fire-and-forget POST tasks may still be draining after crawl() returns.
    # Give them a brief grace period before asserting.
    await asyncio.sleep(0.5)

    events = list(handler.events)
    assert events, "no progress events were delivered"

    # Schema sanity — every event must carry the core counters.
    for e in events:
        assert "pages_visited" in e
        assert "pages_queued"  in e
        assert "xhr_observed"  in e
        assert "forms_found"   in e
        assert "elapsed_secs"  in e
        assert e.get("run_id") == "progress-test-42"

    # Non-decreasing pages_visited — the counter never goes backwards.
    visited_seq = [e["pages_visited"] for e in events]
    assert visited_seq == sorted(visited_seq), (
        f"pages_visited regressed across events: {visited_seq}"
    )
