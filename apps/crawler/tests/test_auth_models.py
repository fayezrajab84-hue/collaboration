"""
Unit tests for Phase 2 auth model parsing.

Validates the Pydantic discriminated-union dispatch works correctly — so a
client POSTing `auth: {"type": "form", ...}` gets the right variant.

Runs without a browser.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models import (  # noqa: E402
    CookieAuth,
    CrawlRequest,
    FormAuth,
    HeaderAuth,
    OAuth2Auth,
)


class TestAuthParsing:
    def test_form_auth(self):
        req = CrawlRequest(
            target_url="https://ex.com",
            auth={
                "type": "form",
                "login_url": "https://ex.com/login",
                "username_selector": "#user",
                "password_selector": "#pass",
                "submit_selector": "#submit",
                "username": "alice",
                "password": "s3cret",
                "success_url_contains": "/dashboard",
            },
        )
        assert isinstance(req.auth, FormAuth)
        assert req.auth.username == "alice"
        assert req.auth.type == "form"

    def test_header_auth(self):
        req = CrawlRequest(
            target_url="https://ex.com",
            auth={
                "type": "header",
                "headers": {"Authorization": "Bearer abc123"},
            },
        )
        assert isinstance(req.auth, HeaderAuth)
        assert req.auth.headers["Authorization"] == "Bearer abc123"

    def test_cookie_auth(self):
        req = CrawlRequest(
            target_url="https://ex.com",
            auth={
                "type": "cookie",
                "cookies": [
                    {"name": "sid", "value": "xyz", "domain": "ex.com"},
                ],
            },
        )
        assert isinstance(req.auth, CookieAuth)
        assert req.auth.cookies[0].name == "sid"
        assert req.auth.cookies[0].path == "/"  # default

    def test_oauth2_auth(self):
        req = CrawlRequest(
            target_url="https://ex.com",
            auth={
                "type": "oauth2",
                "token_url": "https://auth.ex.com/oauth/token",
                "client_id": "cid",
                "client_secret": "csec",
                "scope": "read:scan",
            },
        )
        assert isinstance(req.auth, OAuth2Auth)
        assert req.auth.scope == "read:scan"

    def test_no_auth(self):
        req = CrawlRequest(target_url="https://ex.com")
        assert req.auth is None

    def test_unknown_type_rejected(self):
        with pytest.raises(Exception):
            CrawlRequest(
                target_url="https://ex.com",
                auth={"type": "basic", "username": "u", "password": "p"},
            )

    def test_form_auth_missing_required_fields(self):
        with pytest.raises(Exception):
            CrawlRequest(
                target_url="https://ex.com",
                auth={
                    "type": "form",
                    "login_url": "https://ex.com/login",
                    # missing selectors / credentials
                },
            )


class TestHeaderRedaction:
    def test_redact(self):
        from crawler.auth import _redact_header

        assert _redact_header("Authorization", "Bearer " + "x" * 200) == "Authorization=<207 chars>"
        # Never leak the raw value.
        assert "Bearer" not in _redact_header("Authorization", "Bearer secret")
