from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from enum import Enum


def _camel(s: str) -> str:
    return to_camel(s)


class ScanType(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    DAST = "DAST"
    PENTEST = "PENTEST"
    PENTEST_FULL = "PENTEST_FULL"
    # Phase 29 — Cloud Security Posture Management. Wraps Prowler against
    # an authorised Azure subscription / AWS account / GCP project. Slice A
    # is AZURE-only; AWS/GCP are placeholders pending future slices.
    CLOUD = "CLOUD"


class PentestDepth(str, Enum):
    QUICK = "QUICK"            # Nuclei high+critical only — skip Nikto/testssl/exploit (~5-10 min)
    STANDARD = "STANDARD"      # Full Nuclei + Nikto + testssl, no exploit  (~15-30 min)
    AGGRESSIVE = "AGGRESSIVE"  # STANDARD + SQLMap + XSStrike exploitation  (~30-60+ min)


class TargetType(str, Enum):
    REPOSITORY = "REPOSITORY"
    CONTAINER = "CONTAINER"
    DOMAIN = "DOMAIN"
    # Phase 29 — CSPM target. CloudAccount represents (provider, scope) — for
    # AZURE that's a single subscription; AWS = account; GCP = project.
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"   # Two independent probes agree, or exploit succeeded
    LIKELY    = "LIKELY"      # Strong signature match, low FP rate tool
    POSSIBLE  = "POSSIBLE"    # Single heuristic/pattern match


class AuthType(str, Enum):
    FORM   = "FORM"    # submit login form, carry session cookie
    HEADER = "HEADER"  # inject static HTTP header (API key / Bearer)
    COOKIE = "COOKIE"  # inject pre-obtained cookie string
    OAUTH2 = "OAUTH2"  # exchange client credentials / ROPC for a Bearer token


class OAuth2GrantType(str, Enum):
    CLIENT_CREDENTIALS = "client_credentials"   # M2M — clientId + clientSecret
    PASSWORD           = "password"             # ROPC — username + password + client credentials


class AuthConfig(BaseModel):
    """Decrypted auth credentials forwarded from the API worker to the scanner."""
    auth_type: AuthType = AuthType.FORM

    # FORM auth
    login_url: Optional[str] = None          # absolute URL or path, e.g. /login.php
    username_field: str = "username"
    password_field: str = "password"
    username: Optional[str] = None           # never logged
    password: Optional[str] = None           # never logged
    logged_in_pattern: str = "Logout"        # regex confirming successful login
    logged_out_pattern: str = "login"        # URL fragment indicating session expiry

    # HEADER / COOKIE auth
    header_name: Optional[str] = None        # e.g. "Authorization", "Cookie"
    header_value: Optional[str] = None       # e.g. "Bearer <token>" or cookie string

    # OAuth2 auth (auth_type = OAUTH2)
    oauth2_token_url: Optional[str] = None           # token endpoint URL
    oauth2_client_id: Optional[str] = None           # client_id
    oauth2_client_secret: Optional[str] = None       # client_secret — never logged
    oauth2_scope: Optional[str] = None               # space-separated scopes
    oauth2_grant_type: OAuth2GrantType = OAuth2GrantType.CLIENT_CREDENTIALS

    # CSRF token tracking — orthogonal to auth_type. The crawler sidecar reads
    # the token from the configured source on each navigation and re-injects
    # it as ``csrf_header_name`` (default ``X-CSRF-Token``) on subsequent
    # requests. Required for SPAs that protect mutating endpoints with a
    # custom header rather than a hidden form field.
    csrf_meta_selector: Optional[str] = None        # e.g. 'meta[name="csrf-token"]'
    csrf_cookie_name:   Optional[str] = None        # e.g. 'XSRF-TOKEN'
    csrf_header_name:   Optional[str] = None        # null = use crawler default


class CloudProvider(str, Enum):
    """Phase 29 — CSPM provider taxonomy. Slice A is AZURE-only; AWS/GCP
    are placeholders for future slices reusing the same model."""
    AZURE = "AZURE"
    AWS   = "AWS"
    GCP   = "GCP"


class CloudCredentials(BaseModel):
    """Phase 29 — credentials forwarded from the API worker to the scanner
    for one CSPM scan. Decrypted at scan-trigger time from
    ``CloudAccount.encryptedCredentials``; never persisted on the scanner
    side. Sent over the internal Docker network only.

    Provider-specific fields are nullable so the same model carries
    AZURE / AWS / GCP credential shapes — Slice A only populates the
    Azure quartet.
    """
    provider:        CloudProvider

    # Azure Service Principal auth (Slice A)
    tenant_id:       Optional[str] = None     # Entra ID tenant (GUID)
    client_id:       Optional[str] = None     # SP application id (GUID)
    client_secret:   Optional[str] = None     # SP client secret — never logged
    subscription_id: Optional[str] = None     # subscription scope


class ScanRequest(BaseModel):
    scan_job_id: str
    org_id: str
    target_id: str          # DB ID of the target (repo/container/domain)
    scan_type: ScanType
    target_type: TargetType

    # Repository
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    git_token: Optional[str] = None  # internal only, never logged

    # Container
    image_ref: Optional[str] = None

    # Domain
    domain: Optional[str] = None

    # Pentest full — additional scope
    selected_subdomains: list[str] = []
    pentest_depth: PentestDepth = PentestDepth.STANDARD

    # Optional auth config for authenticated DAST / pentest scans
    auth_config: Optional[AuthConfig] = None

    # Phase 29 — Cloud credentials for CSPM scans (target_type=CLOUD_ACCOUNT,
    # scan_type=CLOUD). Populated by the API worker after decrypting
    # CloudAccount.encryptedCredentials; never logged.
    cloud_credentials: Optional[CloudCredentials] = None

    # Populated by the pentest orchestrator after obtaining a session — shared
    # across all phases so each tool doesn't have to re-authenticate.
    # Not sent from the API; set in-process only.
    session_cookie: Optional[str] = None

    # Full URLs extracted from an imported OpenAPI/Swagger spec.
    # Populated by the API worker before dispatching to the scanner.
    # Used by DAST (seed ZAP + Nuclei) and Full Pentest vuln phase.
    api_spec_urls: list[str] = []

    # When set, PENTEST_FULL skips its Playwright crawl phase and instead pulls
    # the URL list out of the live ZAP context with this name. Populated by the
    # API worker for the "Promote recording to Full Pentest" flow — the user
    # already clicked through the app in their browser while proxied through
    # ZAP, so the recorded URLs are the authoritative scope and re-crawling
    # would just re-discover an unauthenticated subset.
    recording_context_name: Optional[str] = None
    recording_target_url:   Optional[str] = None

    # Internal callback URL for phase progress reporting (e.g. http://api:3000)
    api_url: Optional[str] = None

    # Tier 1 — incremental scanning. When non-empty, repo scanners restrict
    # analysis to these paths (relative to the repo root). PR webhooks populate
    # this via the GitHub App files-API. Empty = full repo scan (legacy / push).
    changed_files: list[str] = []
    commit_sha:     Optional[str] = None
    base_commit_sha: Optional[str] = None
    pr_number:       Optional[int] = None


class ReconRequest(BaseModel):
    org_id: str
    domain: str


class ReconSubdomainInfo(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)

    subdomain: str
    is_live: bool = False
    status_code: Optional[int] = None
    technologies: list[str] = []


class ReconResult(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)

    domain: str
    subdomains: list[ReconSubdomainInfo] = []
    duration_ms: int


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)

    fingerprint: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    scan_type: ScanType
    scanner: str

    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None

    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fix_version: Optional[str] = None
    cvss_score: Optional[float] = None

    remediation: Optional[str] = None
    references: list[str] = []
    raw_output: dict[str, Any] = {}

    # Confidence & evidence (for false-positive triage)
    confidence: Confidence = Confidence.POSSIBLE
    evidence: Optional[dict[str, Any]] = None  # {request, response_status, snippet, trigger}


class ScanResult(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)

    scan_job_id: str
    scan_type: ScanType
    scanner: str
    success: bool
    findings: list[NormalizedFinding] = []
    error: Optional[str] = None
    duration_ms: int

    # The set of URLs / paths the scanner actually examined this run.
    # Populated by PENTEST_FULL (from crawler_urls.txt) and DAST recording
    # scans (from the ZAP context's URL list). Empty for everything else.
    #
    # Persisted to ScanJob.targetUrls and used by the diff endpoint to
    # distinguish "genuinely fixed" findings (URL was in scope, vuln gone)
    # from "out of scope this run" findings (URL was never re-scanned, so
    # we can't claim anything about whether the vuln still exists).
    target_urls: list[str] = []


class VerifyRequest(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)

    rule_id: str
    target_url: str
    scan_type: ScanType


class VerifyResponse(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)

    rule_id: str
    confirmed: bool
    confidence: Confidence
    evidence: dict[str, Any] = {}
