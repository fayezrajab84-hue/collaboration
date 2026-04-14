from __future__ import annotations
import json

from models import NormalizedFinding, ScanRequest, ScanType
from .base import BaseScanner


class SCAScanner(BaseScanner):
    """SCA scanner using Trivy (filesystem mode)."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.repo_url or not request.branch:
            raise ValueError("repo_url and branch required for SCA scan")

        repo_dir = f"{workspace}/repo"
        self.clone_repo(request.repo_url, request.branch, request.git_token, repo_dir)

        result = self.run_cmd([
            "trivy", "fs",
            "--format", "json",
            "--scanners", "vuln",
            "--quiet",
            ".",
        ], cwd=repo_dir)

        findings: list[NormalizedFinding] = []
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return findings

        for result_item in data.get("Results", []):
            for vuln in result_item.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID", "")
                pkg_name = vuln.get("PkgName", "")
                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")
                severity_str = vuln.get("Severity", "INFO")
                cvss = vuln.get("CVSS", {})
                cvss_score = None
                for _, scores in cvss.items():
                    if isinstance(scores, dict):
                        v = scores.get("V3Score") or scores.get("V2Score")
                        if v is not None:
                            cvss_score = float(v)
                            break

                severity = self.map_cvss_to_severity(cvss_score)
                if severity_str.upper() == "CRITICAL":
                    from models import Severity
                    severity = Severity.CRITICAL
                elif severity_str.upper() == "HIGH":
                    from models import Severity
                    severity = Severity.HIGH

                fingerprint = self.compute_fingerprint(
                    request.org_id, request.scan_job_id, ScanType.SCA,
                    cve_id, pkg_name, None
                )

                findings.append(NormalizedFinding(
                    fingerprint=fingerprint,
                    rule_id=cve_id or f"{pkg_name}-vuln",
                    title=f"{cve_id}: {pkg_name}@{installed_ver}" if cve_id else f"Vulnerability in {pkg_name}",
                    description=vuln.get("Description", "No description available."),
                    severity=severity,
                    scan_type=ScanType.SCA,
                    scanner="trivy",
                    cve_id=cve_id or None,
                    package_name=pkg_name,
                    package_version=installed_ver,
                    fix_version=fixed_ver or None,
                    cvss_score=cvss_score,
                    references=vuln.get("References", []),
                    raw_output=vuln,
                ))

        return findings
