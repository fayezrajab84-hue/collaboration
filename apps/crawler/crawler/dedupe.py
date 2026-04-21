"""
URL normalization + scope utilities.

The crawler needs to decide two things on every candidate URL:
 1. Have we already visited an equivalent URL?  (normalize + compare)
 2. Is this URL in scope for the current scan?   (include/exclude + host)

The rules below intentionally err on the side of *collapsing* URLs: we'd
rather skip a page that's actually different than re-visit the same page
300× with rotating tracking params.
"""
from __future__ import annotations

import fnmatch
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Query parameters that never change page identity — strip before dedup.
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid", "ref", "refsource", "source",
    "_ga", "_gl", "yclid",
}


def normalize_url(raw: str) -> str:
    """
    Return a canonical form of ``raw`` suitable for deduplication.

    - Lowercases scheme + host.
    - Drops fragments (``#section``).
    - Drops known tracking query params.
    - Sorts remaining query params alphabetically.
    - Strips trailing slash from the path (except root).
    """
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    cleaned_qs = [
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
    ]
    cleaned_qs.sort()
    query = urlencode(cleaned_qs, doseq=True)

    # Fragment intentionally dropped.
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def same_origin(url: str, origin_host: str) -> bool:
    """True when ``url`` points at the same hostname as ``origin_host``."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    return parsed.netloc.lower() == origin_host.lower()


def matches_any(path: str, patterns: list[str]) -> bool:
    """Glob-match ``path`` against any pattern in ``patterns``."""
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def in_scope(
    url: str,
    origin_host: str,
    include_paths: list[str],
    exclude_paths: list[str],
) -> bool:
    """
    Apply include/exclude path rules + same-origin check.

    - If exclude_paths matches, the URL is OUT of scope.
    - If include_paths is non-empty, the URL must match one pattern.
    - Cross-origin URLs are always out of scope.
    """
    if not same_origin(url, origin_host):
        return False
    path = urlparse(url).path or "/"
    if exclude_paths and matches_any(path, exclude_paths):
        return False
    if include_paths and not matches_any(path, include_paths):
        return False
    return True
