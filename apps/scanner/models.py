from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel
from enum import Enum


class ScanType(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    DAST = "DAST"
    PENTEST = "PENTEST"


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


class ScanRequest(BaseModel):
    scan_job_id: str
    org_id: str
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


class NormalizedFinding(BaseModel):
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


class ScanResult(BaseModel):
    scan_job_id: str
    scan_type: ScanType
    scanner: str
    success: bool
    findings: list[NormalizedFinding] = []
    error: Optional[str] = None
    duration_ms: int
