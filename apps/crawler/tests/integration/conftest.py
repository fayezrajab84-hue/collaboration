"""
Integration-test fixtures.

Spins up a local HTTP server serving ``apps/crawler/tests/fixtures/vulnspa``
in a background thread, so the Playwright crawler can hit a real,
deterministic, offline target without requiring docker-compose.

A dedicated server is started per test session and torn down on exit.
Pages are served from a fixed port picked by the OS (socket.bind(('', 0))).
"""
from __future__ import annotations

import socket
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "vulnspa"


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _QuietHandler(SimpleHTTPRequestHandler):
    # Silence per-request stderr noise during tests.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_POST(self):  # noqa: N802 — match BaseHTTPRequestHandler naming
        # VulnSPA has a POST /api/stats XHR and POST form actions that we
        # never want to 500 on during tests — treat any POST as 204.
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(204)
        self.end_headers()


@pytest.fixture(scope="session")
def vulnspa_url() -> str:
    """Session-scoped HTTP server serving the VulnSPA fixture directory."""
    assert FIXTURE_ROOT.is_dir(), f"Fixture dir missing: {FIXTURE_ROOT}"
    port = _pick_free_port()
    handler = partial(_QuietHandler, directory=str(FIXTURE_ROOT))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
