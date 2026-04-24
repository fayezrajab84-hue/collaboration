from __future__ import annotations
import json

from models import Confidence, NormalizedFinding, ScanRequest, ScanType
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

        # ── Incremental mode — only emit findings for manifests the PR touched ──
        # SCA vulnerabilities only change when a manifest (package.json, go.sum,
        # requirements.txt, Gemfile.lock, pom.xml, …) changes. If the PR didn't
        # touch any of them, short-circuit the per-result loop.
        changed_set: set[str] | None = None
        if request.changed_files:
            changed_set = {p.lstrip("./") for p in request.changed_files}

        for result_item in data.get("Results", []):
            # Trivy reports the manifest file path at the result level (e.g. "pom.xml", "package.json")
            dep_file = result_item.get("Target", "") or None
            if changed_set is not None and dep_file:
                # Require an exact match on the manifest path or any parent lockfile
                norm = dep_file.lstrip("./")
                if norm not in changed_set:
                    continue
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
                    request.org_id, request.target_id, ScanType.SCA,
                    cve_id, pkg_name, None
                )

                # A CVE ID means Trivy matched against the NVD database — confirmed match
                confidence = Confidence.CONFIRMED if cve_id else Confidence.LIKELY

                findings.append(NormalizedFinding(
                    fingerprint=fingerprint,
                    rule_id=cve_id or f"{pkg_name}-vuln",
                    title=f"{cve_id}: {pkg_name}@{installed_ver}" if cve_id else f"Vulnerability in {pkg_name}",
                    description=vuln.get("Description", "No description available."),
                    severity=severity,
                    scan_type=ScanType.SCA,
                    scanner="trivy",
                    file_path=dep_file,
                    cve_id=cve_id or None,
                    package_name=pkg_name,
                    package_version=installed_ver,
                    fix_version=fixed_ver or None,
                    cvss_score=cvss_score,
                    references=vuln.get("References", []),
                    raw_output=vuln,
                    confidence=confidence,
                    evidence={
                        "cve_id": cve_id,
                        "package": pkg_name,
                        "installed_version": installed_ver,
                        "fixed_version": fixed_ver or "no fix available",
                        "cvss_score": cvss_score,
                        "data_source": vuln.get("DataSource", {}).get("Name", "NVD") if vuln.get("DataSource") else "NVD",
                    },
                ))

        return findings
