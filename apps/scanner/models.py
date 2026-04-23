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
    DAST_INTERACTIVE = "DAST_INTERACTIVE"
    PENTEST = "PENTEST"
    PENTEST_FULL = "PENTEST_FULL"


class PentestDepth(str, Enum):
    STANDARD = "STANDARD"
    AGGRESSIVE = "AGGRESSIVE"


class TargetType(str, Enum):
    REPOSITORY = "REPOSITORY"
    CONTAINER = "CONTAINER"
    DOMAIN = "DOMAIN"


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

    # Populated by the pentest orchestrator after obtaining a session — shared
    # across all phases so each tool doesn't have to re-authenticate.
    # Not sent from the API; set in-process only.
    session_cookie: Optional[str] = None

    # Full URLs extracted from an imported OpenAPI/Swagger spec.
    # Populated by the API worker before dispatching to the scanner.
    # Used by DAST (seed ZAP + Nuclei) and Full Pentest vuln phase.
    api_spec_urls: list[str] = []

    # Internal callback URL for phase progress reporting (e.g. http://api:3000)
    api_url: Optional[str] = None


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
