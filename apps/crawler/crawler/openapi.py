"""
Phase 3 OpenAPI pre-seeding.

Modern API-first shops ship an OpenAPI (Swagger) spec — it's a dream
discovery source: every path, every method, sometimes with example
payloads. When a client supplies ``openapi_spec_url``, we fetch the
document, resolve ``servers[0].url`` against the target, and enqueue every
``paths.*`` entry as a seed.

Kept deliberately simple:

- Only supports OpenAPI v3 (swagger: "2.0" is converted to the v3 shape
  well enough for URL extraction by just mapping ``basePath``).
- No ``$ref`` resolution, no payload generation — we only need URLs.
- All HTTP methods get enqueued (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD),
  but DELETE is marked destructive and only kept as a ``source="openapi"``
  record for reporting (not auto-hit by the crawler's GET-only visits).

The response is intentionally tolerant of partially-broken specs — a real
Swagger UI often serves JSON that would fail strict validation.
"""
from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger("crawler.openapi")

_SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


async def fetch_and_extract_urls(
    spec_url: str,
    target_url: str,
    proxy: Optional[str] = None,
) -> tuple[list[str], list[str]]:
    """
    Download the spec and return ``(get_urls, non_get_urls)``.

    ``get_urls`` go into the BFS queue (safe to hit).
    ``non_get_urls`` are reported as discovered (source="openapi") but the
    crawler won't navigate to them — the DAST scanner picks them up from
    the report and decides whether to probe.
    """
    try:
        async with httpx.AsyncClient(
            timeout=20.0,
            proxy=proxy,
            verify=False,  # ZAP proxies present a self-signed cert
        ) as client:
            resp = await client.get(spec_url, headers={"Accept": "application/json"})
    except Exception as exc:
        log.warning("openapi fetch failed: %s", exc)
        return [], []

    if resp.status_code >= 400:
        log.warning("openapi fetch returned %s", resp.status_code)
        return [], []

    try:
        spec = resp.json()
    except Exception as exc:
        log.warning("openapi response was not JSON: %s", exc)
        return [], []

    base = _resolve_base_url(spec, target_url, spec_url)
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return [], []

    gets: list[str] = []
    others: list[str] = []
    for raw_path, ops in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if not isinstance(ops, dict):
            continue
        # OpenAPI path templating: replace {id} with a safe placeholder so the
        # URL is hittable. ZAP's spider / later scanners will still see the
        # shape and do proper fuzzing.
        concrete = _fill_path_params(raw_path)
        full = urljoin(base + "/" if not base.endswith("/") else base, concrete.lstrip("/"))
        for method in ops.keys():
            if not isinstance(method, str):
                continue
            m = method.lower()
            if m not in _SUPPORTED_METHODS:
                continue
            if m == "get":
                gets.append(full)
            else:
                others.append(full)

    # De-dupe while preserving order.
    return (_ordered_dedupe(gets), _ordered_dedupe(others))


def _resolve_base_url(spec: dict, target_url: str, spec_url: str) -> str:
    """
    Build the base URL against which paths are joined.

    Priority: spec.servers[0].url > swagger v2 (host+basePath) > target URL's origin.
    """
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        s0 = servers[0]
        if isinstance(s0, dict):
            url = s0.get("url")
            if isinstance(url, str) and url:
                # Relative server URLs are resolved against the spec URL itself
                # per OpenAPI 3.0 §4.8.5.
                if url.startswith("/") or not urlparse(url).scheme:
                    return urljoin(spec_url, url).rstrip("/")
                return url.rstrip("/")

    # Swagger v2 fallback.
    host = spec.get("host")
    base_path = spec.get("basePath") or ""
    schemes = spec.get("schemes") or ["https"]
    if isinstance(host, str) and host:
        return f"{schemes[0]}://{host}{base_path}".rstrip("/")

    # Last resort: target origin.
    p = urlparse(target_url)
    return f"{p.scheme}://{p.netloc}".rstrip("/")


def _fill_path_params(path: str) -> str:
    """Replace {foo} path segments with a placeholder."""
    out: list[str] = []
    depth = 0
    token = []
    for ch in path:
        if ch == "{":
            depth += 1
            token = []
            continue
        if ch == "}" and depth > 0:
            depth -= 1
            out.append("1")  # safe numeric placeholder
            token = []
            continue
        if depth > 0:
            token.append(ch)
            continue
        out.append(ch)
    return "".join(out)


def _ordered_dedupe(xs: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in xs:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


__all__ = ["fetch_and_extract_urls"]
