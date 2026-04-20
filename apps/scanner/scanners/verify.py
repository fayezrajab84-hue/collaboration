"""
Verify module: re-runs a specific check identified by rule_id to confirm
whether a finding still exists. Returns confirmed, confidence, and evidence.

Called by POST /verify on the scanner service.
Used by the API's POST /findings/:id/verify endpoint for false-positive triage.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from models import Confidence, ScanRequest, ScanType, TargetType, VerifyRequest, VerifyResponse
from .dast_checks import (
    _get as dast_get,
    check_hsts,
    check_csp,
    check_clickjacking,
    check_cookies,
    check_info_leak_headers,
    check_sri,
    check_reverse_tabnabbing,
    check_exposed_paths,
    check_directory_listing,
    check_heartbleed,
    check_jwt_in_response,
)


# ── helpers ───────────────────────────────────────────────────────────────────

class _StubScanner:
    """Minimal scanner stub used to compute fingerprints during re-verification."""
    def compute_fingerprint(self, org_id, target_id, scan_type, rule_id, file_path, line):
        import hashlib
        raw = f"{org_id}:{target_id}:{scan_type}:{rule_id}:{file_path or ''}:{line or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()


def _stub_request(target_url: str, scan_type: ScanType) -> ScanRequest:
    parsed = urlparse(target_url)
    domain = parsed.netloc or target_url
    return ScanRequest(
        scan_job_id="verify",
        org_id="verify",
        target_id="verify",
        scan_type=scan_type,
        target_type=TargetType.DOMAIN,
        domain=domain,
    )


def _fetch(url: str) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as c:
            return c.get(url)
    except Exception:
        return None


# ── DAST rule dispatch ────────────────────────────────────────────────────────

# Map rule_id prefix → check function (those that take base_url + resp)
_DAST_HEADER_CHECKS = {
    "hsts": check_hsts,
    "csp": check_csp,
    "missing-clickjacking-header": check_clickjacking,
    "xfo": check_clickjacking,
    "cookie": check_cookies,
    "server-header-app": check_info_leak_headers,
    "server-version-leak": check_info_leak_headers,
    "x-powered-by-leak": check_info_leak_headers,
    "aspnet-version-leak": check_info_leak_headers,
    "x-backend-header": check_info_leak_headers,
    "sri-missing": check_sri,
    "reverse-tabnabbing": check_reverse_tabnabbing,
    "directory-listing": check_directory_listing,
    "jwt": check_jwt_in_response,
}

# Rules that only need a URL (no page body required)
_DAST_URL_ONLY_CHECKS = {
    "env-exposed", "htaccess-exposed", "git-source-exposed", "svn-source-exposed",
    "heartbleed",
}


def _verify_dast(rule_id: str, target_url: str) -> VerifyResponse:
    scanner = _StubScanner()
    request = _stub_request(target_url, ScanType.DAST)

    # URL-only probes
    if rule_id in _DAST_URL_ONLY_CHECKS:
        if rule_id == "heartbleed":
            findings = check_heartbleed(scanner, request, target_url)
        else:
            findings = check_exposed_paths(scanner, request, target_url)
            findings = [f for f in findings if f.rule_id == rule_id]
        confirmed = len(findings) > 0
        confidence = findings[0].confidence if findings else Confidence.POSSIBLE
        evidence = findings[0].evidence if findings else {"detail": "No longer detected"}
        return VerifyResponse(
            rule_id=rule_id,
            confirmed=confirmed,
            confidence=confidence,
            evidence=evidence or {},
        )

    # Header/body checks — need to fetch the page
    resp = _fetch(target_url)
    if not resp:
        return VerifyResponse(
            rule_id=rule_id,
            confirmed=False,
            confidence=Confidence.POSSIBLE,
            evidence={"detail": "Target unreachable during re-verification"},
        )

    # Find the matching check function
    check_fn = None
    for prefix, fn in _DAST_HEADER_CHECKS.items():
        if rule_id == prefix or rule_id.startswith(prefix):
            check_fn = fn
            break

    if check_fn is None:
        # Unknown rule — run the full targeted checks and look for a match
        from .dast_checks import run_all_checks
        all_findings = run_all_checks(scanner, request, target_url, resp)
        match = next((f for f in all_findings if f.rule_id == rule_id), None)
        confirmed = match is not None
        return VerifyResponse(
            rule_id=rule_id,
            confirmed=confirmed,
            confidence=match.confidence if match else Confidence.POSSIBLE,
            evidence=match.evidence if match else {"detail": "No longer detected"},
        )

    # Run the matched check
    findings = check_fn(scanner, request, target_url, resp)
    match = next((f for f in findings if f.rule_id == rule_id), None)
    confirmed = match is not None
    return VerifyResponse(
        rule_id=rule_id,
        confirmed=confirmed,
        confidence=match.confidence if match else Confidence.POSSIBLE,
        evidence=match.evidence if match else {"detail": "No longer detected after re-check"},
    )


# ── PENTEST_FULL rule dispatch ────────────────────────────────────────────────

def _verify_pentest(rule_id: str, target_url: str) -> VerifyResponse:
    from .pentest_full.pentest_checks import (
        check_cors, check_graphql, check_ssrf, check_open_redirect,
        check_rate_limiting, check_idor_surface, check_ssti,
        check_llm_endpoints, check_debug_endpoints, check_security_headers,
        _base_url as pentest_base_url,
    )

    scanner = _StubScanner()
    request = _stub_request(target_url, ScanType.PENTEST_FULL)
    base = pentest_base_url(urlparse(target_url).netloc or target_url)
    resp = _fetch(base)

    # Map rule_id → check function
    _PENTEST_CHECKS = {
        "pentest:cors-wildcard": lambda: check_cors(scanner, request, base),
        "pentest:cors-reflect-with-credentials": lambda: check_cors(scanner, request, base),
        "pentest:cors-reflect-origin": lambda: check_cors(scanner, request, base),
        "pentest:graphql-introspection": lambda: check_graphql(scanner, request, base),
        "pentest:ssrf-confirmed": lambda: check_ssrf(scanner, request, base, resp),
        "pentest:ssrf-parameter-risk": lambda: check_ssrf(scanner, request, base, resp),
        "pentest:open-redirect": lambda: check_open_redirect(scanner, request, base),
        "pentest:no-rate-limit": lambda: check_rate_limiting(scanner, request, base),
        "pentest:idor-surface": lambda: check_idor_surface(scanner, request, base, resp),
        "pentest:ssti-confirmed": lambda: check_ssti(scanner, request, base),
        "pentest:llm-prompt-injection-confirmed": lambda: check_llm_endpoints(scanner, request, base),
        "pentest:llm-endpoint-exposed": lambda: check_llm_endpoints(scanner, request, base),
        "pentest:missing-xcto": lambda: check_security_headers(scanner, request, base, resp),
        "pentest:missing-referrer-policy": lambda: check_security_headers(scanner, request, base, resp),
        "pentest:missing-permissions-policy": lambda: check_security_headers(scanner, request, base, resp),
    }

    # Debug endpoint rules follow pattern pentest:debug-endpoint:/<path>
    if rule_id.startswith("pentest:debug-endpoint:"):
        check_fn = lambda: check_debug_endpoints(scanner, request, base)
    else:
        check_fn = _PENTEST_CHECKS.get(rule_id)

    if check_fn is None:
        return VerifyResponse(
            rule_id=rule_id,
            confirmed=False,
            confidence=Confidence.POSSIBLE,
            evidence={"detail": f"Unknown rule_id for re-verification: {rule_id}"},
        )

    try:
        findings = check_fn()
        match = next((f for f in findings if f.rule_id == rule_id), None)
        confirmed = match is not None
        return VerifyResponse(
            rule_id=rule_id,
            confirmed=confirmed,
            confidence=match.confidence if match else Confidence.POSSIBLE,
            evidence=match.evidence if match else {"detail": "No longer detected after re-check"},
        )
    except Exception as exc:
        return VerifyResponse(
            rule_id=rule_id,
            confirmed=False,
            confidence=Confidence.POSSIBLE,
            evidence={"detail": f"Re-verification failed: {str(exc)[:200]}"},
        )


# ── Public entry point ────────────────────────────────────────────────────────

def verify_finding(req: VerifyRequest) -> VerifyResponse:
    """
    Dispatch to the correct scanner check based on scan_type and rule_id.
    Returns a VerifyResponse with confirmed, confidence, and evidence.
    """
    if req.scan_type == ScanType.DAST:
        return _verify_dast(req.rule_id, req.target_url)
    elif req.scan_type == ScanType.PENTEST_FULL:
        return _verify_pentest(req.rule_id, req.target_url)
    else:
        return VerifyResponse(
            rule_id=req.rule_id,
            confirmed=False,
            confidence=Confidence.POSSIBLE,
            evidence={"detail": f"Live re-verification is not supported for scan type: {req.scan_type}"},
        )
