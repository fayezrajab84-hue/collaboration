from __future__ import annotations
import json

from models import NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


class SecretsScanner(BaseScanner):
    """Secret scanner using TruffleHog."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.repo_url or not request.branch:
            raise ValueError("repo_url and branch required for secrets scan")

        repo_dir = f"{workspace}/repo"
        self.clone_repo(request.repo_url, request.branch, request.git_token, repo_dir)

        result = self.run_cmd([
            "trufflehog", "filesystem",
            "--json",
            "--no-update",
            repo_dir,
        ])

        findings: list[NormalizedFinding] = []
        # TruffleHog outputs newline-delimited JSON
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = item.get("DetectorName", "unknown")
            source_data = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file_path = source_data.get("file", "")
            line_num = source_data.get("line")
            verified = item.get("Verified", False)
            raw_secret = item.get("Raw", "")

            # Higher severity for verified (active) secrets
            severity = Severity.CRITICAL if verified else Severity.HIGH

            fingerprint = self.compute_fingerprint(
                request.org_id, request.scan_job_id, ScanType.SECRET,
                detector, file_path, line_num
            )

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=detector,
                title=f"Secret detected: {detector}",
                description=(
                    f"{'⚠️ VERIFIED ACTIVE SECRET' if verified else 'Potential secret'}: "
                    f"{detector} found in {file_path}. "
                    f"Immediately rotate this credential."
                ),
                severity=severity,
                scan_type=ScanType.SECRET,
                scanner="trufflehog",
                file_path=file_path,
                line_start=int(line_num) if line_num else None,
                remediation="Immediately rotate this credential and remove it from source code. Use environment variables or a secrets manager.",
                raw_output={k: v for k, v in item.items() if k != "Raw"},  # don't store raw secret
            ))

        return findings
