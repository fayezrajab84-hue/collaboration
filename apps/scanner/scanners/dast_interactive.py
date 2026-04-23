"""
Interactive DAST — proxy-recorded session backed by OWASP ZAP.

Lifecycle:
  1. start_recording(domain)              — create a ZAP context scoped to the domain,
                                            return proxy details + context id.
  2. get_session_stats(context_id)        — poll ZAP for recorded URLs + passive alerts.
  3. run_recorded_scan(request, ctx_id)   — kick off an ASCAN against the context's
                                            recorded URLs (skip spider/discovery).
  4. stop_recording(context_id)           — remove context. Doesn't drop the ZAP
                                            session itself; concurrent recordings
                                            for other targets stay isolated by their
                                            own contexts.

The user's browser is configured to proxy through host 127.0.0.1:8090, which
forwards into the ZAP container on port 8080. Because ZAP merges proxy + API
on the same listener, every URL the browser fetches lands in ZAP's site tree
under the corresponding context.
"""
from __future__ import annotations
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from config import settings
from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .dast import (
    DASTScanner,
    ZAP_SEVERITY_MAP,
    ZAP_CONFIDENCE_MAP,
    ZAP_DOWNGRADE_TO_INFO_IDS,
    _zap_should_include,
    ASCAN_MAX_DURATION_MINS,
)


def _domain_to_context_regex(domain: str) -> str:
    """Build a ZAP include-in-context regex matching http(s)://<domain>/.*"""
    # ZAP uses Java regex; escape dots so they match literally.
    safe = domain.replace(".", r"\.")
    return rf"https?://{safe}/.*"


def _resolve_target_url(domain: str) -> str:
    """Probe https→http; same fallback DASTScanner uses."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
                resp = client.get(url)
                if resp.status_code < 500:
                    return url
        except Exception:
            continue
    return f"http://{domain}"


class InteractiveDASTSession:
    """Thin wrapper around ZAP's context API for interactive sessions."""

    def __init__(self) -> None:
        self.zap_url = settings.zap_base_url
        self.api_key = settings.zap_api_key

    def _zap(self, path: str, params: dict[str, Any] | None = None,
             timeout: int = 30) -> dict:
        url = f"{self.zap_url}{path}"
        p = {"apikey": self.api_key, **(params or {})}
        with httpx.Client(timeout=timeout) as client:
            res = client.get(url, params=p)
            res.raise_for_status()
            return res.json()

    def _fetch_alerts_paginated(
        self,
        target_url: str,
        page_size: int = 200,
        overall_timeout: int = 420,
    ) -> list[dict]:
        """
        Harvest all alerts for ``target_url`` from ZAP using pagination.

        Why this exists: a single ``/JSON/core/view/alerts/?baseurl=X`` call on a
        context with 1000+ alerts blows past httpx's default 30 s timeout because
        ZAP has to serialize the entire alert list (with messageId, evidence,
        etc.) into one response. That failure previously raised a ReadTimeout
        that killed the whole scan and dropped every alert on the floor.

        Fix: page through the alert set with ``start``/``count``, use a longer
        per-call timeout, retry transient failures with exponential backoff, and
        stop gracefully at the overall deadline — returning whatever we have
        collected so far. Harvest MUST NOT raise: the active scan has already
        run and ZAP's findings are real; dropping them because of a slow read
        is the worst possible outcome.
        """
        alerts: list[dict] = []
        start = 0
        deadline = time.time() + overall_timeout
        backoff = 2.0

        while time.time() < deadline:
            try:
                page_resp = self._zap(
                    "/JSON/core/view/alerts/",
                    {
                        "baseurl": target_url,
                        "start":   str(start),
                        "count":   str(page_size),
                    },
                    timeout=90,
                )
            except Exception as exc:
                remaining = deadline - time.time()
                if remaining <= 0:
                    print(f"[dast-interactive] alert fetch deadline hit at start={start} "
                          f"after {exc.__class__.__name__} — returning {len(alerts)} collected")
                    break
                sleep_for = min(backoff, max(1.0, remaining))
                print(f"[dast-interactive] alert fetch transient error at start={start}: "
                      f"{exc.__class__.__name__} — retrying in {sleep_for:.1f}s")
                time.sleep(sleep_for)
                backoff = min(backoff * 2, 20.0)
                continue

            page = page_resp.get("alerts") or []
            if not page:
                break
            alerts.extend(page)
            if len(page) < page_size:
                break  # last page
            start += page_size
            backoff = 2.0  # reset after a successful read

        return alerts

    # ── 1. start ─────────────────────────────────────────────────────────────

    def start(self, domain: str, context_name: str) -> dict[str, Any]:
        """
        Create a fresh ZAP context scoped to the domain. Returns:
          { contextId, contextName, targetUrl, regex }
        """
        target_url = _resolve_target_url(domain)
        regex      = _domain_to_context_regex(domain)

        ctx_resp = self._zap("/JSON/context/action/newContext/", {"contextName": context_name})
        ctx_id   = ctx_resp.get("contextId", "1")
        self._zap("/JSON/context/action/includeInContext/", {
            "contextName": context_name,
            "regex":       regex,
        })
        return {
            "contextId":   ctx_id,
            "contextName": context_name,
            "targetUrl":   target_url,
            "regex":       regex,
        }

    # ── 2. stats ─────────────────────────────────────────────────────────────

    def stats(self, context_name: str, target_url: str) -> dict[str, int]:
        """
        Return current { urlCount, alertCount } for this session.

        urls: filter ZAP's site tree by the target host. (`/JSON/core/view/urls/`
        with baseurl filters URLs whose URL string starts with baseurl, which is
        what we want — a proxy-recorded URL for this domain.)
        alerts: ZAP runs the passive scanner automatically as the browser proxies;
        we count alerts whose URL falls under target_url.
        """
        # Use core/urls (all known URLs); filter by baseurl so we don't count
        # other domains the browser may have hit before proxy was configured.
        try:
            urls_resp = self._zap("/JSON/core/view/urls/", {"baseurl": target_url})
            url_list  = urls_resp.get("urls", []) or []
        except Exception:
            url_list = []

        try:
            alerts_resp = self._zap("/JSON/core/view/numberOfAlerts/", {"baseurl": target_url})
            alert_n     = int(alerts_resp.get("numberOfAlerts", "0"))
        except Exception:
            alert_n = 0

        return {"urlCount": len(url_list), "alertCount": alert_n}

    # ── 3. run recorded scan ─────────────────────────────────────────────────

    def run_active_scan(
        self,
        context_id:   str,
        context_name: str,
        target_url:   str,
        request:      ScanRequest,
    ) -> list[NormalizedFinding]:
        """
        Run an active scan against the recorded URLs (no spider, no discovery).
        Reuses DASTScanner's _configure_ascan + _tune_ascan_policy and the same
        alert-normalization logic.
        """
        helper = DASTScanner()  # composition for reused tuning + helpers
        helper._configure_ascan()
        helper._tune_ascan_policy()

        # Kick off ascan against the context — ZAP picks up every URL under the
        # context's include regex, no spider needed. ZAP rejects the url if it
        # doesn't match the context regex literally — our regex ends in `/.*`,
        # so the bare host (`http://dvwa`) fails with `url_not_in_context`.
        # Enforce a trailing slash to satisfy the regex.
        scan_url = target_url if target_url.endswith("/") else target_url + "/"
        ascan_id = "0"
        try:
            ascan_resp = self._zap(
                "/JSON/ascan/action/scan/",
                {"url": scan_url, "contextId": context_id, "recurse": "true"},
                timeout=60,
            )
            ascan_id = ascan_resp.get("scan", "0")
            helper._report_progress(request, 10, "active_scan_started")
        except Exception as exc:
            # ZAP is overloaded — skip the active scan and harvest whatever
            # passive + previously-captured alerts already exist.
            print(f"[dast-interactive] could not start active scan ({exc.__class__.__name__}: "
                  f"{exc}) — proceeding to harvest existing alerts")

        # Poll until done or duration cap. Same loop budget as a normal DAST scan.
        # Individual poll failures are transient — log and continue rather than
        # raising, so we still reach the harvest step.
        if ascan_id and ascan_id != "0":
            max_polls = (ASCAN_MAX_DURATION_MINS + 2) * 12  # 12 polls/min (5 s)
            consecutive_errors = 0
            for _ in range(max_polls):
                try:
                    status = self._zap(
                        "/JSON/ascan/view/status/", {"scanId": ascan_id}, timeout=30,
                    )
                    pct = int(status.get("status", "0"))
                    helper._report_progress(request, 10 + int(pct * 0.80), "active_scanning")
                    consecutive_errors = 0
                    if pct >= 100:
                        break
                except Exception as exc:
                    consecutive_errors += 1
                    print(f"[dast-interactive] status poll error #{consecutive_errors}: "
                          f"{exc.__class__.__name__} — continuing")
                    if consecutive_errors >= 10:
                        print("[dast-interactive] too many consecutive poll errors — "
                              "stopping scan loop, harvesting partial results")
                        break
                time.sleep(5)
            else:
                try:
                    self._zap("/JSON/ascan/action/stop/", {"scanId": ascan_id}, timeout=20)
                except Exception:
                    pass

        helper._report_progress(request, 90, "active_scan_done")

        # Collect alerts scoped to the target — paginated + resilient.
        # See _fetch_alerts_paginated docstring for why this is not a single call.
        alerts = self._fetch_alerts_paginated(target_url)
        print(f"[dast-interactive] harvested {len(alerts)} alerts from ZAP for {target_url}")

        findings: list[NormalizedFinding] = []
        for alert in alerts:
            risk_code = alert.get("risk") or alert.get("riskcode", "0")
            alert_id  = alert.get("alertRef", alert.get("pluginid", alert.get("alert", "zap-alert")))
            url       = alert.get("url", "")

            zap_confidence_str = alert.get("confidence", "Medium")
            confidence         = ZAP_CONFIDENCE_MAP.get(zap_confidence_str, Confidence.POSSIBLE)
            severity           = ZAP_SEVERITY_MAP.get(risk_code, Severity.INFO)
            if alert_id in ZAP_DOWNGRADE_TO_INFO_IDS:
                severity = Severity.INFO

            if not _zap_should_include(alert_id, severity, confidence):
                continue

            fingerprint = helper.compute_fingerprint(
                request.org_id, request.target_id, ScanType.DAST_INTERACTIVE,
                alert_id, url, None,
            )

            evidence: dict = {
                "url":              url,
                "zap_confidence":   zap_confidence_str,
                "response_status":  alert.get("statusCode", ""),
                "interactive":      True,
                "context_name":     context_name,
            }
            for k in ("evidence", "attack", "param"):
                if alert.get(k):
                    evidence[k] = alert[k]
            if alert.get("other"):
                evidence["other"] = str(alert["other"])[:300]

            # Pull the full HTTP exchange ZAP captured for this alert so the
            # drawer can show "what we sent / what came back" instead of just
            # the rule name.  Delegates to DASTScanner._fetch_message (shared
            # with the regular DAST path) — keeps truncation + NUL-stripping
            # rules in one place.
            exchange = helper._fetch_message(alert.get("messageId"))
            if exchange:
                evidence["http_exchange"] = exchange
                baseline = helper._capture_baseline(
                    exchange, alert.get("param"), alert.get("attack"),
                )
                if baseline:
                    evidence["http_baseline_exchange"] = baseline

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=alert_id,
                title=alert.get("alert", "ZAP Alert (interactive)"),
                description=alert.get("description", ""),
                severity=severity,
                scan_type=ScanType.DAST_INTERACTIVE,
                scanner="zap-interactive",
                cwe_id=f"CWE-{alert.get('cweid', '')}" if alert.get("cweid") else None,
                remediation=alert.get("solution", ""),
                references=[alert.get("reference", "")] if alert.get("reference") else [],
                raw_output=alert,
                confidence=confidence,
                evidence=evidence,
            ))
        return findings

    # ── 4. stop ──────────────────────────────────────────────────────────────

    def stop(self, context_name: str) -> None:
        """Remove the context. Does NOT clear ZAP's session — other contexts
        survive. We let ZAP keep recorded URLs in case the user re-starts a
        session for the same domain in this ZAP lifetime."""
        try:
            self._zap("/JSON/context/action/removeContext/", {"contextName": context_name})
        except Exception:
            # Already gone (eg duplicate stop) — non-fatal.
            pass

    # ── helpers ──────────────────────────────────────────────────────────────

    def root_cert_url(self) -> str:
        """ZAP's CA download endpoint (DER format). The API proxies this so the
        browser sees it as coming from the platform, not from ZAP directly."""
        return f"{self.zap_url}/OTHER/core/other/rootcert/?apikey={self.api_key}"
