"""
Pydantic request / response models for the crawler service.

These are the contract between the Python scanner (which invokes /crawl)
and the crawler sidecar. Keep them backwards-compatible when evolving —
add new optional fields rather than renaming existing ones.
"""
from __future__ import annotations

from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, Field, HttpUrl


# ── Request ────────────────────────────────────────────────────────────────

class CrawlRequest(BaseModel):
    # Target to start crawling from. Must be an absolute URL (http/https).
    target_url: HttpUrl

    # Limits — the crawler will stop at whichever triggers first.
    max_depth: Optional[int] = Field(default=None, ge=0, le=20)
    max_pages: Optional[int] = Field(default=None, ge=1, le=2000)
    max_duration_secs: Optional[int] = Field(default=None, ge=1, le=3600)

    # Scope constraints — list of URL path globs. When include_paths is set
    # the crawler will only follow URLs matching at least one pattern.
    # exclude_paths overrides include_paths.
    include_paths: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)

    # When true, every request goes through the ZAP proxy configured on the
    # crawler service. When false, the crawler runs stand-alone (useful for
    # dry-run testing and unit tests).
    use_zap_proxy: bool = True

    # Correlation id stamped on the X-Crawler-Run-Id header of every request
    # the browser emits. Lets downstream scanners attribute observed traffic
    # back to a specific scan.
    run_id: Optional[str] = None

    # Authentication — one of FormAuth / HeaderAuth / CookieAuth / OAuth2Auth,
    # discriminated by `type`. None means unauthenticated.
    auth: Optional["AuthConfig"] = None

    # Reserved for Phase 3.
    openapi_spec_url: Optional[str] = None
    interact_with_forms: bool = False

    # Phase 5 — live progress callback. When set, the crawler POSTs periodic
    # progress events to ``<progress_callback_url>`` so the API can forward
    # them to the frontend via SSE. Non-fatal on failure.
    progress_callback_url: Optional[str] = None
    # Emit a progress event at most this often (seconds).
    progress_throttle_secs: float = 2.0


# ── Authentication ─────────────────────────────────────────────────────────

class FormAuth(BaseModel):
    """
    Classic HTML form login.

    The crawler navigates to ``login_url``, fills the named fields, submits,
    and checks ``success_indicator`` against the post-submit page to decide
    whether auth worked. All subsequent requests reuse the logged-in
    BrowserContext (so session cookies flow automatically).
    """
    type: Literal["form"] = "form"
    login_url: HttpUrl
    username_selector: str = Field(
        description="CSS selector for the username input, e.g. 'input[name=username]'"
    )
    password_selector: str = Field(description="CSS selector for the password input")
    submit_selector: str = Field(description="CSS selector for the submit button")
    username: str
    password: str

    # Success detection — at least one must match after submit.
    # - success_url_contains: substring that must appear in the URL after login
    # - success_selector: CSS selector that must exist on the post-login page
    # - success_text: plain-text substring that must appear in the page body
    success_url_contains: Optional[str] = None
    success_selector: Optional[str] = None
    success_text: Optional[str] = None


class HeaderAuth(BaseModel):
    """Static header auth — injected on every request (bearer tokens, API keys)."""
    type: Literal["header"] = "header"
    # e.g. {"Authorization": "Bearer eyJ...", "X-Api-Key": "..."}
    headers: dict[str, str]


class Cookie(BaseModel):
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = True
    http_only: bool = True
    # Playwright requires at least one of (url) or (domain + path) — we give both.


class CookieAuth(BaseModel):
    """Pre-authenticated cookie jar — skips the login flow entirely."""
    type: Literal["cookie"] = "cookie"
    cookies: list[Cookie]


class OAuth2Auth(BaseModel):
    """
    OAuth2 client-credentials flow.

    The crawler POSTs to ``token_url`` with the configured credentials,
    extracts ``access_token`` from the JSON response, and then behaves like
    HeaderAuth with ``Authorization: Bearer <token>``.
    """
    type: Literal["oauth2"] = "oauth2"
    token_url: HttpUrl
    client_id: str
    client_secret: str
    scope: Optional[str] = None
    audience: Optional[str] = None
    extra_headers: dict[str, str] = Field(default_factory=dict)


AuthConfig = Annotated[
    Union[FormAuth, HeaderAuth, CookieAuth, OAuth2Auth],
    Field(discriminator="type"),
]
CrawlRequest.model_rebuild()


# ── Response ───────────────────────────────────────────────────────────────

DiscoveredSource = Literal[
    "seed",
    "link",
    "xhr",
    "fetch",
    "navigation",
    "openapi",
    "form",
    "spa-router",
]


class DiscoveredUrl(BaseModel):
    url: str
    method: str = "GET"
    depth: int
    source: DiscoveredSource
    status: Optional[int] = None
    content_type: Optional[str] = None
    error: Optional[str] = None


class XhrCall(BaseModel):
    url: str
    method: str
    content_type: Optional[str] = None
    status: Optional[int] = None


StopReason = Literal[
    "complete",
    "max_pages",
    "max_depth",
    "max_duration",
    "error",
]


class CrawlStats(BaseModel):
    pages_visited: int
    forms_found: int = 0
    xhr_observed: int
    duration_secs: float
    stopped_reason: StopReason


class CrawlResult(BaseModel):
    discovered_urls: list[DiscoveredUrl]
    api_endpoints: list[XhrCall]
    auth_success: Optional[bool] = None
    auth_evidence: Optional[str] = None
    stats: CrawlStats
    warnings: list[str] = Field(default_factory=list)
