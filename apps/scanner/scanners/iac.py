from __future__ import annotations
import json

from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


CHECKOV_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class IACScanner(BaseScanner):
    """IaC scanner using Checkov."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.repo_url or not request.branch:
            raise ValueError("repo_url and branch required for IaC scan")

        repo_dir = f"{workspace}/repo"
        self.clone_repo(request.repo_url, request.branch, request.git_token, repo_dir)

        result = self.run_cmd([
            "checkov",
            "-d", repo_dir,
            "-o", "json",
            "--quiet",
            # NOTE: do NOT add --compact — it suppresses code_block which we need for the code preview
        ])

        findings: list[NormalizedFinding] = []

        # Checkov may return multiple JSON objects separated by newlines when scanning multiple frameworks
        stdout = result.stdout or ""
        # Try to parse as single JSON first, then as newline-delimited
        json_objects = []
        try:
            obj = json.loads(stdout)
            json_objects = [obj] if isinstance(obj, dict) else obj if isinstance(obj, list) else []
        except json.JSONDecodeError:
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        json_objects.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for data in json_objects:
            if isinstance(data, list):
                # Multiple framework results
                for item in data:
                    findings.extend(self._parse_checkov_result(item, request))
            elif isinstance(data, dict):
                findings.extend(self._parse_checkov_result(data, request))

        return findings

    def _parse_checkov_result(self, data: dict, request: ScanRequest) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        failed_checks = data.get("results", {}).get("failed_checks", [])

        # check_type lives at the top-level result object (e.g. "terraform", "kubernetes")
        top_level_check_type = data.get("check_type", "") or ""

        for check in failed_checks:
            check_id = check.get("check_id", "")
            # Per-check check_type may also be present; fall back to top-level
            check_type = check.get("check_type") or top_level_check_type or ""
            resource = check.get("resource", "")
            file_path = check.get("file_path", "")
            file_line_range = check.get("file_line_range", [None, None])
            guideline = check.get("guideline", "")
            severity_str = check.get("severity") or "MEDIUM"

            severity = CHECKOV_SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)
            fingerprint = self.compute_fingerprint(
                request.org_id, request.target_id, ScanType.IAC,
                check_id, file_path, file_line_range[0] if file_line_range else None
            )

            # Extract code snippet from Checkov's code_block field.
            # Format: [[lineNo, "content\n"], ...]  →  "42: resource ... \n43:   ..."
            code_block = check.get("code_block") or []
            code_snippet: str | None = None
            if code_block:
                lines = []
                for entry in code_block:
                    if isinstance(entry, (list, tuple)) and len(entry) == 2:
                        no, text = entry
                        lines.append(f"{no}: {str(text).rstrip()}")
                code_snippet = "\n".join(lines)[:1000] or None

            # check_name is Checkov's human-readable rule description, e.g.
            # "Ensure all data stored in the Launch configuration EBS is securely encrypted"
            # Some checks (custom policies, secrets framework, older Checkov versions)
            # omit check_name or set it equal to check_id — fall back through the
            # Bridgecrew name / description fields, and only use the raw rule ID as a
            # last resort so the finding title isn't just "CKV_AWS_20".
            raw_name = (check.get("check_name") or "").strip()
            if not raw_name or raw_name == check_id:
                raw_name = (
                    (check.get("bc_check_name") or "").strip()
                    or (check.get("description")   or "").strip()
                    or (check.get("short_description") or "").strip()
                )
            check_name = raw_name or check_id

            # Build a concise title: human name is enough — no need to prefix the rule ID
            # (rule_id is stored separately and shown in the drawer)
            title = check_name

            # Rich description: what the check verifies + which resource failed + framework
            resource_label = f" on `{resource}`" if resource else ""
            framework_label = f" ({check_type})" if check_type else ""
            description = (
                f"{check_name}{resource_label}. "
                f"Checkov rule {check_id}{framework_label} flagged this misconfiguration."
            )
            if guideline:
                description += f" See: {guideline}"

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=check_id,
                title=title,
                description=description,
                severity=severity,
                scan_type=ScanType.IAC,
                scanner="checkov",
                file_path=file_path,
                line_start=file_line_range[0] if file_line_range else None,
                line_end=file_line_range[1] if len(file_line_range) > 1 else None,
                code_snippet=code_snippet,
                remediation=guideline or None,
                references=[guideline] if guideline else [],
                raw_output=check,
                # Checkov is deterministic pattern matching — failed check = confirmed misconfiguration
                confidence=Confidence.CONFIRMED,
                evidence={
                    "check_id": check_id,
                    "check_type": check_type,
                    "resource": resource,
                    "file": file_path,
                    "lines": file_line_range,
                    "result": check.get("check_result", {}).get("result", "failed"),
                },
            ))

        return findings
