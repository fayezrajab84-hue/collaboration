"""
Unit tests for OpenAPI pre-seeding helpers (no network).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crawler.openapi import _fill_path_params, _ordered_dedupe, _resolve_base_url  # noqa: E402


class TestFillPathParams:
    def test_single_param(self):
        assert _fill_path_params("/users/{id}") == "/users/1"

    def test_multiple_params(self):
        assert _fill_path_params("/orgs/{org}/repos/{repo}") == "/orgs/1/repos/1"

    def test_no_params(self):
        assert _fill_path_params("/health") == "/health"

    def test_nested_braces_tolerated(self):
        # Not a real OpenAPI case, but shouldn't crash.
        assert _fill_path_params("/a/{b}/c") == "/a/1/c"


class TestResolveBaseUrl:
    def test_openapi_v3_absolute_server(self):
        spec = {"servers": [{"url": "https://api.example.com/v2"}]}
        assert _resolve_base_url(spec, "https://example.com", "https://example.com/spec.json") \
            == "https://api.example.com/v2"

    def test_openapi_v3_relative_server_resolves_against_spec(self):
        spec = {"servers": [{"url": "/api/v1"}]}
        assert _resolve_base_url(spec, "https://example.com", "https://example.com/docs/spec.json") \
            == "https://example.com/api/v1"

    def test_swagger_v2_host_basepath(self):
        spec = {"host": "api.example.com", "basePath": "/v1", "schemes": ["https"]}
        assert _resolve_base_url(spec, "https://example.com", "https://example.com/spec.json") \
            == "https://api.example.com/v1"

    def test_fallback_to_target_origin(self):
        spec: dict = {}
        assert _resolve_base_url(spec, "https://example.com/app", "https://example.com/spec.json") \
            == "https://example.com"


class TestOrderedDedupe:
    def test_preserves_order(self):
        assert _ordered_dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]

    def test_empty(self):
        assert _ordered_dedupe([]) == []
