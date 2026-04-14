from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid
from abc import ABC, abstractmethod
from typing import Optional

from config import settings
from models import NormalizedFinding, ScanRequest, ScanType, Severity


class BaseScanner(ABC):
    """Abstract base for all security scanners."""

    @abstractmethod
    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        """Run the scanner and return normalized findings."""
        ...

    # ── Utilities ──────────────────────────────────────────────────────────

    def run_cmd(
        self,
        cmd: list[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
    ) -> subprocess.CompletedProcess:
        """Run a shell command safely, never logging secrets."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout or settings.scan_timeout_seconds,
            env={**os.environ, **(env or {})},
        )

    def clone_repo(
        self,
        repo_url: str,
        branch: str,
        git_token: Optional[str],
        target_dir: str,
    ) -> str:
        """Clone repo to target_dir. Returns the cloned path."""
        if git_token:
            # Inject token into URL — never log this
            parsed = repo_url.replace("https://", f"https://x-access-token:{git_token}@")
        else:
            parsed = repo_url

        cmd = [
            "git", "clone",
            "--depth", str(settings.max_clone_depth),
            "--branch", branch,
            "--single-branch",
            parsed,
            target_dir,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            # Sanitize error message before raising (remove token if present)
            err = result.stderr.replace(git_token or "", "***") if git_token else result.stderr
            raise RuntimeError(f"Git clone failed: {err[:500]}")
        return target_dir

    @staticmethod
    def compute_fingerprint(
        org_id: str,
        target_id: str,
        scan_type: ScanType,
        rule_id: str,
        file_path: Optional[str],
        line: Optional[int],
    ) -> str:
        raw = f"{org_id}:{target_id}:{scan_type}:{rule_id}:{file_path or ''}:{line or 0}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def map_semgrep_severity(sev: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
        }
        return mapping.get(sev.upper(), Severity.INFO)

    @staticmethod
    def map_cvss_to_severity(score: Optional[float]) -> Severity:
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def make_workspace() -> str:
        path = os.path.join(settings.scan_workspace_dir, str(uuid.uuid4()))
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def cleanup(path: str) -> None:
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass
