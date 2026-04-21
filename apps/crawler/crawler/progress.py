"""
Progress reporter — posts crawl progress to an external callback URL.

Called from the BFS loop on every visit; a throttle keeps the POST rate
bounded regardless of how fast the crawl runs. Failures are logged but
never propagate — the crawl itself is the priority.

Event shape (kept minimal — the API re-shapes it for SSE fan-out):

    {
      "phase": "crawling",
      "pages_visited": 42,
      "pages_queued": 137,
      "xhr_observed": 19,
      "forms_found": 3,
      "current_url": "https://ex.com/dashboard",
      "elapsed_secs": 12.4,
      "run_id": "<scan-job-id>"
    }
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

log = logging.getLogger("crawler.progress")


class ProgressReporter:
    def __init__(
        self,
        callback_url: Optional[str],
        run_id: Optional[str],
        throttle_secs: float = 2.0,
    ) -> None:
        self.callback_url = callback_url
        self.run_id = run_id
        self.throttle_secs = max(0.1, throttle_secs)
        self._last_emit: float = 0.0
        self._started: float = time.monotonic()
        # Re-use one client for the whole crawl — a new TCP connection per
        # event would dominate the crawl's wall time on a long run.
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ProgressReporter":
        if self.callback_url:
            # 2s total per event — callback must not slow the crawl.
            self._client = httpx.AsyncClient(timeout=2.0)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None

    async def emit(
        self,
        *,
        pages_visited: int,
        pages_queued: int,
        xhr_observed: int,
        forms_found: int,
        current_url: Optional[str],
        force: bool = False,
    ) -> None:
        """Emit a progress event if the throttle window has elapsed."""
        if self._client is None:
            return
        now = time.monotonic()
        if not force and (now - self._last_emit) < self.throttle_secs:
            return
        self._last_emit = now

        payload = {
            "phase": "crawling",
            "pages_visited": pages_visited,
            "pages_queued": pages_queued,
            "xhr_observed": xhr_observed,
            "forms_found": forms_found,
            "current_url": current_url,
            "elapsed_secs": round(now - self._started, 2),
            "run_id": self.run_id,
        }

        # Fire-and-forget — never wait on the callback if the consumer is slow.
        try:
            asyncio.create_task(self._post(payload))
        except RuntimeError:
            # Called outside an event loop (unit tests); skip silently.
            pass

    async def _post(self, payload: dict) -> None:
        assert self._client is not None
        assert self.callback_url is not None
        try:
            await self._client.post(self.callback_url, json=payload)
        except Exception as exc:
            log.debug("progress callback failed: %s", exc)


__all__ = ["ProgressReporter"]
