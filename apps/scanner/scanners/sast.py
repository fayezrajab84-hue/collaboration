from __future__ import annotations
import json

from models import NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


class SASTScanner(BaseScanner):
    """SAST scanner using Semgrep."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.repo_url or not request.branch:
            raise ValueError("repo_url and branch required for SAST scan")

        repo_dir = f"{workspace}/repo"
        self.clone_repo(request.repo_url, request.branch, request.git_token, repo_dir)

        result = self.run_cmd(
            ["semgrep", "--config", "auto", "--json", "--no-git-ignore", "."],
            cwd=repo_dir,
        )

        findings: list[NormalizedFinding] = []
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return findings

        for item in data.get("results", []):
            check_id = item.get("check_id", "unknown")
            path = item.get("path", "")
            line_start = item.get("start", {}).get("line")
            line_end = item.get("end", {}).get("line")
            message = item.get("extra", {}).get("message", "")
            sev_str = item.get("extra", {}).get("severity", "INFO")
            metadata = item.get("extra", {}).get("metadata", {})

            severity = self.map_semgrep_severity(sev_str)
            fingerprint = self.compute_fingerprint(
                request.org_id, request.scan_job_id, ScanType.SAST,
                check_id, path, line_start
            )

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=check_id,
                title=check_id.split(".")[-1].replace("-", " ").title(),
                description=message,
                severity=severity,
                scan_type=ScanType.SAST,
                scanner="semgrep",
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                cwe_id=metadata.get("cwe", [None])[0] if isinstance(metadata.get("cwe"), list) else metadata.get("cwe"),
                remediation=metadata.get("fix"),
                references=metadata.get("references", []),
                raw_output=item,
            ))

        return findings
