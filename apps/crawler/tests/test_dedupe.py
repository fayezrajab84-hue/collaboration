"""
Unit tests for URL normalization + scope helpers.

Runs without a browser, so safe to execute in CI without Playwright
binaries installed:

    pip install pytest
    pytest apps/crawler/tests
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make `crawler.dedupe` importable when running pytest from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crawler.dedupe import in_scope, normalize_url, same_origin  # noqa: E402


class TestNormalizeUrl:
    def test_lowercases_host(self):
        assert normalize_url("HTTPS://Example.COM/") == "https://example.com/"

    def test_strips_fragment(self):
        assert normalize_url("https://ex.com/a#section") == "https://ex.com/a"

    def test_strips_trailing_slash_except_root(self):
        assert normalize_url("https://ex.com/a/") == "https://ex.com/a"
        assert normalize_url("https://ex.com/") == "https://ex.com/"

    def test_drops_tracking_params(self):
        assert (
            normalize_url("https://ex.com/a?utm_source=x&keep=1")
            == "https://ex.com/a?keep=1"
        )

    def test_sorts_query_params(self):
        assert (
            normalize_url("https://ex.com/a?b=2&a=1")
            == "https://ex.com/a?a=1&b=2"
        )

    def test_same_url_normalizes_equal(self):
        a = "https://Ex.com/p?utm_source=x&a=1#top"
        b = "https://ex.com/p/?a=1"
        assert normalize_url(a) == normalize_url(b)


class TestSameOrigin:
    def test_match(self):
        assert same_origin("https://ex.com/a", "ex.com")

    def test_different_host(self):
        assert not same_origin("https://other.com/a", "ex.com")

    def test_non_http(self):
        assert not same_origin("javascript:void(0)", "ex.com")


class TestInScope:
    def test_same_origin_with_no_filters(self):
        assert in_scope("https://ex.com/a", "ex.com", [], [])

    def test_cross_origin_blocked(self):
        assert not in_scope("https://other.com/a", "ex.com", [], [])

    def test_exclude_wins(self):
        assert not in_scope("https://ex.com/logout", "ex.com", ["/*"], ["/logout"])

    def test_include_enforced(self):
        assert in_scope("https://ex.com/app/users", "ex.com", ["/app/*"], [])
        assert not in_scope("https://ex.com/other", "ex.com", ["/app/*"], [])
