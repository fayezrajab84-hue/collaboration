from __future__ import annotations
import time

import httpx

from config import settings
from models import NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


ZAP_SEVERITY_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


class DASTScanner(BaseScanner):
    """DAST scanner using OWASP ZAP REST API."""

    def __init__(self):
        self.zap_url = settings.zap_base_url
        self.api_key = settings.zap_api_key

    def _zap(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.zap_url}{path}"
        p = {"apikey": self.api_key, **(params or {})}
        with httpx.Client(timeout=30) as client:
            res = client.get(url, params=p)
            res.raise_for_status()
            return res.json()

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.domain:
            raise ValueError("domain required for DAST scan")

        target_url = f"https://{request.domain}"

        # 1. Spider the target
        spider_resp = self._zap("/JSON/spider/action/scan/", {"url": target_url, "maxChildren": "10"})
        spider_id = spider_resp.get("scan", "0")

        # 2. Wait for spider to complete (max 5 min)
        for _ in range(60):
            status = self._zap("/JSON/spider/view/status/", {"scanId": spider_id})
            if int(status.get("status", "0")) >= 100:
                break
            time.sleep(5)

        # 3. Start active scan
        ascan_resp = self._zap("/JSON/ascan/action/scan/", {"url": target_url})
        ascan_id = ascan_resp.get("scan", "0")

        # 4. Wait for active scan (max 10 min)
        for _ in range(120):
            status = self._zap("/JSON/ascan/view/status/", {"scanId": ascan_id})
            if int(status.get("status", "0")) >= 100:
                break
            time.sleep(5)

        # 5. Collect alerts
        alerts_resp = self._zap("/JSON/core/view/alerts/", {"baseurl": target_url})
        alerts = alerts_resp.get("alerts", [])

        findings: list[NormalizedFinding] = []
        for alert in alerts:
            risk = alert.get("risk", "Informational")
            risk_code = alert.get("riskcode", "0")
            alert_id = alert.get("alertRef", alert.get("alert", "zap-alert"))
            url = alert.get("url", "")
            description = alert.get("description", "")
            solution = alert.get("solution", "")

            severity = ZAP_SEVERITY_MAP.get(risk_code, Severity.INFO)
            fingerprint = self.compute_fingerprint(
                request.org_id, request.scan_job_id, ScanType.DAST,
                alert_id, url, None
            )

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=alert_id,
                title=alert.get("alert", "ZAP Alert"),
                description=description,
                severity=severity,
                scan_type=ScanType.DAST,
                scanner="zap",
                cwe_id=f"CWE-{alert.get('cweid', '')}" if alert.get("cweid") else None,
                remediation=solution,
                references=[alert.get("reference", "")] if alert.get("reference") else [],
                raw_output=alert,
            ))

        return findings
