from __future__ import annotations
import json

from models import NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


class ContainerScanner(BaseScanner):
    """Container image scanner using Trivy."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.image_ref:
            raise ValueError("image_ref required for container scan")

        result = self.run_cmd([
            "trivy", "image",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig",
            "--quiet",
            request.image_ref,
        ])

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
                sev_str = vuln.get("Severity", "INFO")
                cvss_score = None
                for _, scores in vuln.get("CVSS", {}).items():
                    if isinstance(scores, dict):
                        v = scores.get("V3Score") or scores.get("V2Score")
                        if v:
                            cvss_score = float(v)
                            break

                sev_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                severity = sev_map.get(sev_str.upper(), Severity.INFO)
                fingerprint = self.compute_fingerprint(
                    request.org_id, request.scan_job_id, ScanType.CONTAINER,
                    cve_id or pkg_name, request.image_ref, None
                )

                findings.append(NormalizedFinding(
                    fingerprint=fingerprint,
                    rule_id=cve_id or f"{pkg_name}-vuln",
                    title=f"{cve_id}: {pkg_name}@{installed_ver}" if cve_id else f"Vulnerability in {pkg_name}",
                    description=vuln.get("Description", "No description available."),
                    severity=severity,
                    scan_type=ScanType.CONTAINER,
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
