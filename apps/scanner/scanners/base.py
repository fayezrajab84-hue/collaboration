from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional

from config import settings
from models import NormalizedFinding, ScanRequest, ScanType, Severity

_CLONE_CACHE_DIR = "/tmp/scan_clone_cache"
_CLONE_CACHE_TTL = 1800  # 30 minutes


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
        """Clone repo to target_dir, using a local cache to avoid redundant clones."""
        cache_key = hashlib.sha256(f"{repo_url}:{branch}".encode()).hexdigest()[:24]
        cache_path = os.path.join(_CLONE_CACHE_DIR, cache_key)

        # Use cached clone if fresh
        if os.path.isdir(cache_path):
            age = time.time() - os.path.getmtime(cache_path)
            if age < _CLONE_CACHE_TTL:
                shutil.copytree(cache_path, target_dir, dirs_exist_ok=True)
                return target_dir
            shutil.rmtree(cache_path, ignore_errors=True)

        # Fresh clone
        if git_token:
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            err = result.stderr.replace(git_token or "", "***") if git_token else result.stderr
            raise RuntimeError(f"Git clone failed: {err[:500]}")

        # Cache for subsequent scan types on the same repo
        os.makedirs(_CLONE_CACHE_DIR, exist_ok=True)
        try:
            shutil.copytree(target_dir, cache_path, dirs_exist_ok=True)
        except Exception:
            pass  # cache write failure is non-fatal

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
