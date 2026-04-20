"""
Targeted HTTP-level checks that cover every item listed in the frontend's
DOMAIN_CHECKS (DAST & API Checks) tab.

These run after ZAP completes its spider + active scan so ZAP findings and
these findings are merged into one list returned to the API.
"""
from __future__ import annotations

import base64
import hmac
import json
import re
from urllib.parse import urlparse

import httpx

from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


# ── helpers ──────────────────────────────────────────────────────────────────

def _get(url: str, *, timeout: int = 10, verify: bool = False) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=verify) as c:
            return c.get(url)
    except Exception:
        return None


def _head(url: str, *, timeout: int = 10, verify: bool = False) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=verify) as c:
            return c.head(url)
    except Exception:
        return None


def _finding(
    scanner: BaseScanner,
    request: ScanRequest,
    check_id: str,
    title: str,
    description: str,
    severity: Severity,
    remediation: str = "",
    url: str = "",
    cwe_id: str | None = None,
    confidence: Confidence = Confidence.POSSIBLE,
    evidence: dict | None = None,
) -> NormalizedFinding:
    fingerprint = scanner.compute_fingerprint(
        request.org_id, request.target_id, ScanType.DAST,
        check_id, url or request.domain or "", None,
    )
    return NormalizedFinding(
        fingerprint=fingerprint,
        rule_id=check_id,
        title=title,
        description=description,
        severity=severity,
        scan_type=ScanType.DAST,
        scanner="dast-checks",
        cwe_id=cwe_id,
        remediation=remediation,
        references=[],
        raw_output={"check_id": check_id, "url": url},
        confidence=confidence,
        evidence=evidence or {"check": check_id, "url": url},
    )


# ── individual checks ─────────────────────────────────────────────────────────

def check_hsts(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    hsts_headers = resp.headers.get_list("strict-transport-security") if hasattr(resp.headers, "get_list") else [resp.headers.get("strict-transport-security", "")]
    # httpx Headers object: iterate directly
    raw = [v for k, v in resp.headers.items() if k.lower() == "strict-transport-security"]

    hdr_evidence = {"check": "hsts", "url": base_url, "headers": dict(list(resp.headers.items())[:10])}
    if not raw:
        findings.append(_finding(scanner, request, "hsts-missing",
            "HSTS Header Is Missing",
            "The Strict-Transport-Security header is absent. Browsers may allow HTTP connections, exposing users to SSL-stripping attacks.",
            Severity.HIGH,
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses.",
            base_url, "CWE-319",
            Confidence.POSSIBLE, hdr_evidence))
        return findings

    if len(raw) > 1:
        findings.append(_finding(scanner, request, "hsts-multiple",
            "Multiple HSTS Headers Are Being Set",
            "Multiple Strict-Transport-Security response headers were detected. Conflicting headers create undefined browser behavior.",
            Severity.MEDIUM,
            "Return exactly one Strict-Transport-Security header.",
            base_url, None,
            Confidence.CONFIRMED, {"check": "hsts-multiple", "url": base_url, "values": raw}))

    hsts_value = raw[0]

    if "max-age=0" in hsts_value:
        findings.append(_finding(scanner, request, "hsts-disabled",
            "HSTS Header Is Disabled",
            "The server sets max-age=0, disabling HSTS and allowing downgrade to unencrypted HTTP.",
            Severity.MEDIUM,
            "Set max-age to at least 31536000 (1 year).",
            base_url, None,
            Confidence.CONFIRMED, {"check": "hsts-disabled", "url": base_url, "header_value": hsts_value}))

    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.I)
    if not max_age_match:
        findings.append(_finding(scanner, request, "hsts-bad-max-age",
            "HSTS Header Has Malformed Max-Age Directive",
            "The max-age directive is missing or malformed in the Strict-Transport-Security header.",
            Severity.MEDIUM,
            "Ensure the header includes a valid `max-age=<seconds>` directive.",
            base_url, None,
            Confidence.CONFIRMED, {"check": "hsts-bad-max-age", "url": base_url, "header_value": hsts_value}))

    if not base_url.startswith("https"):
        findings.append(_finding(scanner, request, "hsts-not-enforced",
            "TLS Not Enforced With Valid HSTS Header",
            "The site responds over HTTP without redirecting to HTTPS, so HSTS cannot be enforced.",
            Severity.CRITICAL,
            "Redirect all HTTP traffic to HTTPS and serve HSTS on the HTTPS response.",
            base_url, "CWE-319",
            Confidence.CONFIRMED, {"check": "hsts-not-enforced", "url": base_url, "scheme": base_url.split("://")[0]}))

    return findings


def check_csp(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    csp = resp.headers.get("content-security-policy", "")
    csp_ro = resp.headers.get("content-security-policy-report-only", "")
    legacy = resp.headers.get("x-content-security-policy", "") or resp.headers.get("x-webkit-csp", "")

    csp_evidence_base = {"check": "csp", "url": base_url, "csp_header": csp or None}
    if not csp:
        findings.append(_finding(scanner, request, "csp-missing",
            "Content Security Policy (CSP) Header Not Set",
            "No Content-Security-Policy header was found. Without CSP, browsers execute any script served alongside the page.",
            Severity.CRITICAL,
            "Add a restrictive Content-Security-Policy header. Start with `default-src 'self'`.",
            base_url, "CWE-1021",
            Confidence.POSSIBLE, csp_evidence_base))
    else:
        if "unsafe-inline" in csp and "script-src" in csp:
            findings.append(_finding(scanner, request, "csp-unsafe-inline-js",
                "CSP Config Allows Inline JavaScript",
                "The CSP header contains `unsafe-inline` for script-src, allowing inline script execution and weakening XSS protection.",
                Severity.HIGH,
                "Remove `unsafe-inline` from script-src and use nonces or hashes instead.",
                base_url, None,
                Confidence.CONFIRMED, {**csp_evidence_base, "detail": "unsafe-inline in script-src"}))
        if "unsafe-eval" in csp:
            findings.append(_finding(scanner, request, "csp-allows-eval",
                "CSP Policy Does Not Block eval()",
                "The CSP header includes `unsafe-eval`, allowing `eval()` and similar dynamic code execution.",
                Severity.HIGH,
                "Remove `unsafe-eval` from your CSP and refactor code to avoid eval().",
                base_url, None,
                Confidence.CONFIRMED, {**csp_evidence_base, "detail": "unsafe-eval present"}))
        if "default-src" not in csp:
            findings.append(_finding(scanner, request, "csp-no-fallback",
                "CSP Policy Does Not Define a Fallback Directive",
                "The CSP header has no `default-src` fallback. Browsers treat missing directives as unrestricted.",
                Severity.HIGH,
                "Add `default-src 'self'` as a fallback to your CSP.",
                base_url, None,
                Confidence.CONFIRMED, {**csp_evidence_base, "detail": "missing default-src"}))
        if "unsafe-inline" in csp and "style-src" in csp:
            findings.append(_finding(scanner, request, "csp-unsafe-inline-css",
                "CSP Config Allows Inline CSS",
                "The CSP header allows inline CSS via `unsafe-inline` in style-src. Injected CSS can be used for data exfiltration.",
                Severity.LOW,
                "Remove `unsafe-inline` from style-src and use external stylesheets.",
                base_url, None,
                Confidence.CONFIRMED, {**csp_evidence_base, "detail": "unsafe-inline in style-src"}))

    if csp_ro and not csp:
        findings.append(_finding(scanner, request, "csp-report-only",
            "Content Security Policy (CSP) Report-Only Header Found",
            "A Content-Security-Policy-Report-Only header is present but no enforcing CSP. The policy is not enforced.",
            Severity.CRITICAL,
            "Promote the policy to a full Content-Security-Policy header.",
            base_url, None,
            Confidence.CONFIRMED, {"check": "csp-report-only", "url": base_url, "csp_ro": csp_ro}))

    if legacy:
        findings.append(_finding(scanner, request, "obsolete-csp-header",
            "Obsolete Content Security Policy (CSP) Header Found",
            "The response uses X-Content-Security-Policy or X-WebKit-CSP, which are non-standard and ignored by modern browsers.",
            Severity.MEDIUM,
            "Replace with the standard Content-Security-Policy header.",
            base_url, None,
            Confidence.CONFIRMED, {"check": "obsolete-csp", "url": base_url, "legacy_header": legacy}))

    return findings


def check_clickjacking(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    xfo_values = [v for k, v in resp.headers.items() if k.lower() == "x-frame-options"]
    csp = resp.headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp

    xfo_evidence = {"check": "clickjacking", "url": base_url, "x_frame_options": xfo_values, "csp_frame_ancestors": has_frame_ancestors}
    if not xfo_values and not has_frame_ancestors:
        findings.append(_finding(scanner, request, "missing-clickjacking-header",
            "Missing Anti-Clickjacking Header",
            "No X-Frame-Options or CSP frame-ancestors directive found. Attackers can embed this page in an iframe for clickjacking.",
            Severity.MEDIUM,
            "Add `Content-Security-Policy: frame-ancestors 'self'` or `X-Frame-Options: DENY`.",
            base_url, "CWE-1021",
            Confidence.POSSIBLE, xfo_evidence))
        return findings

    if len(xfo_values) > 1:
        findings.append(_finding(scanner, request, "xfo-multiple",
            "Multiple X-Frame-Options Header Entries",
            "Multiple X-Frame-Options headers were returned. Browser behavior is undefined with conflicting headers.",
            Severity.MEDIUM,
            "Return exactly one X-Frame-Options header.",
            base_url, None,
            Confidence.CONFIRMED, {**xfo_evidence, "values": xfo_values}))

    if xfo_values:
        valid = {"DENY", "SAMEORIGIN"}
        val = xfo_values[0].strip().upper()
        if not any(val == v or val.startswith("ALLOW-FROM") for v in valid | {"ALLOW-FROM"}):
            findings.append(_finding(scanner, request, "xfo-malformed",
                "X-Frame-Options Setting Malformed",
                f"The X-Frame-Options header value '{xfo_values[0]}' is invalid. Browsers may ignore it.",
                Severity.MEDIUM,
                "Use DENY or SAMEORIGIN as the X-Frame-Options value.",
                base_url, None,
                Confidence.CONFIRMED, {**xfo_evidence, "invalid_value": xfo_values[0]}))

    return findings


def check_cookies(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    set_cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

    for cookie in set_cookies:
        cookie_lower = cookie.lower()
        name = cookie.split("=")[0].strip()

        cookie_ev = {"check": "cookie", "url": base_url, "cookie_name": name, "set_cookie_header": cookie[:200]}
        if "secure" not in cookie_lower:
            findings.append(_finding(scanner, request, "cookie-no-secure",
                "Cookie Can Be Sent Over Unencrypted Connection",
                f"Cookie '{name}' is missing the Secure flag and may be transmitted over HTTP.",
                Severity.HIGH,
                "Add the Secure flag to all cookies: `Set-Cookie: name=value; Secure`.",
                base_url, "CWE-614",
                Confidence.CONFIRMED, {**cookie_ev, "detail": "Secure flag absent"}))

        if "httponly" not in cookie_lower:
            findings.append(_finding(scanner, request, "cookie-no-httponly",
                "Cookie Missing HttpOnly Flag",
                f"Cookie '{name}' is missing the HttpOnly flag, making it accessible from JavaScript.",
                Severity.HIGH,
                "Add the HttpOnly flag to all cookies: `Set-Cookie: name=value; HttpOnly`.",
                base_url, "CWE-1004",
                Confidence.CONFIRMED, {**cookie_ev, "detail": "HttpOnly flag absent"}))

        # Check for broad domain scoping (e.g. Domain=.example.com)
        domain_match = re.search(r"domain\s*=\s*\.([^;,\s]+)", cookie_lower)
        if domain_match:
            findings.append(_finding(scanner, request, "cookie-broad-domain",
                "Cookie May Be Accessed From Other Subdomains",
                f"Cookie '{name}' is scoped to the parent domain, readable by any subdomain.",
                Severity.MEDIUM,
                "Scope cookies to the specific subdomain unless subdomain sharing is intentional.",
                base_url, None,
                Confidence.CONFIRMED, {**cookie_ev, "domain_scope": domain_match.group(0)}))

    return findings


def check_info_leak_headers(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    server = headers.get("server", "")
    if server:
        # Leaks name only
        findings.append(_finding(scanner, request, "server-header-app",
            "Server Leaks Webserver Application via 'Server' Header",
            f"The Server header discloses: '{server}'.",
            Severity.MEDIUM,
            "Remove or genericise the Server response header.",
            base_url, "CWE-200",
            Confidence.CONFIRMED, {"check": "server-header", "url": base_url, "server_header": server}))
        # Version present in server header?
        if re.search(r"[\d]+\.[\d]", server):
            findings.append(_finding(scanner, request, "server-version-leak",
                "Server Leaks Version Info via 'Server' Header",
                f"The Server header exposes software and exact version: '{server}'.",
                Severity.MEDIUM,
                "Set `ServerTokens Prod` (Apache) or `server_tokens off` (Nginx) to hide version.",
                base_url, "CWE-200",
                Confidence.CONFIRMED, {"check": "server-version", "url": base_url, "server_header": server}))

    x_powered = headers.get("x-powered-by", "")
    if x_powered:
        findings.append(_finding(scanner, request, "x-powered-by-leak",
            "Server Leaks Framework Info via 'X-Powered-By' Header",
            f"The X-Powered-By header reveals: '{x_powered}'.",
            Severity.MEDIUM,
            "Remove the X-Powered-By header (e.g. `app.disable('x-powered-by')` in Express).",
            base_url, "CWE-200",
            Confidence.CONFIRMED, {"check": "x-powered-by", "url": base_url, "header_value": x_powered}))

    aspnet = headers.get("x-aspnet-version", "") or headers.get("x-aspnetmvc-version", "")
    if aspnet:
        findings.append(_finding(scanner, request, "aspnet-version-leak",
            "X-AspNet-Version Response Header Leak",
            f"ASP.NET version information is exposed: '{aspnet}'.",
            Severity.HIGH,
            "Disable via `<httpRuntime enableVersionHeader='false' />` in web.config.",
            base_url, "CWE-200",
            Confidence.CONFIRMED, {"check": "aspnet-version", "url": base_url, "header_value": aspnet}))

    x_backend = headers.get("x-backend-server", "") or headers.get("x-served-by", "")
    if x_backend:
        findings.append(_finding(scanner, request, "x-backend-header",
            "X-Backend-Server Header Information Leak",
            f"Internal backend hostname or IP exposed: '{x_backend}'.",
            Severity.MEDIUM,
            "Strip X-Backend-Server / X-Served-By headers at the load balancer or reverse proxy.",
            base_url, "CWE-200",
            Confidence.CONFIRMED, {"check": "x-backend-header", "url": base_url, "header_value": x_backend}))

    return findings


def check_sri(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    """Check for external scripts/stylesheets without integrity attributes."""
    findings: list[NormalizedFinding] = []
    if not resp or not resp.text:
        return findings

    host = urlparse(base_url).netloc
    # Find <script src="..."> and <link rel="stylesheet" href="..."> without integrity attr
    external_scripts = re.findall(
        r'<script[^>]+src=["\']https?://(?!' + re.escape(host) + r')[^"\']+["\'][^>]*>',
        resp.text, re.I
    )
    for tag in external_scripts:
        if "integrity=" not in tag.lower():
            findings.append(_finding(scanner, request, "sri-missing",
                "Sub-Resource Integrity (SRI) Attribute Missing",
                "An external script is loaded without an `integrity` attribute. If that CDN is compromised, malicious code could run on your page.",
                Severity.LOW,
                "Add `integrity` and `crossorigin` attributes to external <script> and <link> tags.",
                base_url, "CWE-829",
                Confidence.CONFIRMED, {"check": "sri", "url": base_url, "tag_snippet": tag[:200]}))
            break  # one finding per domain is sufficient

    return findings


def check_reverse_tabnabbing(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not resp or not resp.text:
        return findings

    # Links that open in _blank without rel="noopener"
    bad_links = re.findall(
        r'<a[^>]+target=["\']_blank["\'][^>]*>',
        resp.text, re.I
    )
    for tag in bad_links:
        tag_lower = tag.lower()
        if "noopener" not in tag_lower and "noreferrer" not in tag_lower:
            findings.append(_finding(scanner, request, "reverse-tabnabbing",
                "Reverse Tabnabbing Attack Possible via Anchor Tag",
                "Links with target='_blank' lack rel='noopener noreferrer', allowing the opened page to control this page via window.opener.",
                Severity.MEDIUM,
                "Add `rel=\"noopener noreferrer\"` to all `target=\"_blank\"` anchor tags.",
                base_url, "CWE-1022",
                Confidence.CONFIRMED, {"check": "reverse-tabnabbing", "url": base_url, "tag_snippet": tag[:200]}))
            break

    return findings


def check_exposed_paths(scanner: BaseScanner, request: ScanRequest, base_url: str) -> list[NormalizedFinding]:
    """Probe for commonly exposed sensitive files."""
    findings: list[NormalizedFinding] = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    probes = [
        (".env",            "env-exposed",      "CRITICAL", ".env File Publicly Readable",
         "A .env file is accessible, potentially exposing credentials, API keys, and connection strings.",
         "Restrict access to .env files via web server configuration and never deploy them to public directories."),
        (".htaccess",       "htaccess-exposed",  "CRITICAL", ".htaccess File Publicly Readable",
         "An .htaccess file is publicly accessible, revealing server rewrite rules and access controls.",
         "Deny access to .htaccess files: `<Files .htaccess> Require all denied </Files>`."),
        (".git/config",     "git-source-exposed","MEDIUM",  "Source Code Exposed Online — Git",
         "The .git directory is accessible, allowing reconstruction of the full source code and commit history.",
         "Block access to .git directories via Nginx (`location ~ /\\.git { deny all; }`) or Apache."),
        (".svn/entries",    "svn-source-exposed","MEDIUM",  "Source Code Exposed Online — SVN",
         "The .svn directory is accessible, allowing source code reconstruction from SVN metadata.",
         "Block access to .svn directories in your web server configuration."),
    ]

    for path, check_id, sev_str, title, desc, fix in probes:
        url = f"{root}/{path}"
        r = _get(url, timeout=8)
        if r and r.status_code == 200 and len(r.content) > 0:
            sev = getattr(Severity, sev_str)
            findings.append(_finding(scanner, request, check_id, title, desc, sev, fix, url, "CWE-538",
                Confidence.CONFIRMED,
                {"check": check_id, "url": url, "response_status": r.status_code,
                 "content_length": len(r.content), "snippet": r.text[:300] if r.text else ""}))

    return findings


def check_directory_listing(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not resp or not resp.text:
        return findings
    text_lower = resp.text.lower()
    if ("index of /" in text_lower or "directory listing" in text_lower) and resp.status_code == 200:
        findings.append(_finding(scanner, request, "directory-listing",
            "Directory Browsing Detected",
            "The web server returns a directory listing, exposing the file structure and potentially sensitive files.",
            Severity.CRITICAL,
            "Disable directory listing: `Options -Indexes` (Apache) or `autoindex off` (Nginx).",
            base_url, "CWE-548",
            Confidence.CONFIRMED,
            {"check": "directory-listing", "url": base_url, "response_status": resp.status_code,
             "snippet": resp.text[:300]}))
    return findings


def check_heartbleed(scanner: BaseScanner, request: ScanRequest, base_url: str) -> list[NormalizedFinding]:
    """Check via response header for known-vulnerable OpenSSL version."""
    findings: list[NormalizedFinding] = []
    r = _head(base_url, timeout=8)
    if not r:
        return findings
    server = r.headers.get("server", "").lower()
    # Detect OpenSSL 1.0.1 through 1.0.1f which are affected by Heartbleed
    if re.search(r"openssl/1\.0\.1[a-f]?\b", server):
        findings.append(_finding(scanner, request, "heartbleed",
            "Heartbleed OpenSSL Vulnerability",
            "The server advertises an OpenSSL version affected by CVE-2014-0160 (Heartbleed), allowing remote memory disclosure.",
            Severity.CRITICAL,
            "Upgrade OpenSSL to 1.0.1g or later immediately.",
            base_url, "CWE-126",
            Confidence.LIKELY,
            {"check": "heartbleed", "url": base_url, "server_header": server,
             "detail": "OpenSSL version in Server header matches affected range 1.0.1a-1.0.1f"}))
    return findings


def check_jwt_in_response(scanner: BaseScanner, request: ScanRequest, base_url: str, resp: httpx.Response) -> list[NormalizedFinding]:
    """Look for JWT tokens in response bodies and test weak-secret / none-algorithm issues."""
    findings: list[NormalizedFinding] = []
    if not resp or not resp.text:
        return findings

    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    tokens = jwt_pattern.findall(resp.text)

    for token in tokens[:3]:  # test up to 3 tokens
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_raw))
        except Exception:
            continue

        alg = header.get("alg", "").upper()

        # "none" algorithm
        jwt_ev = {"check": "jwt", "url": base_url, "alg": alg, "header": dict(header)}
        if alg == "NONE":
            findings.append(_finding(scanner, request, "jwt-none-algorithm",
                "Server Accepts Tokens With 'none' Algorithm",
                "A JWT token with alg='none' was found in the response. This means the server may not verify signatures.",
                Severity.CRITICAL,
                "Reject any JWT where alg is 'none'. Validate algorithm against an explicit allowlist.",
                base_url, "CWE-347",
                Confidence.LIKELY, {**jwt_ev, "detail": "JWT with alg=none found in response body"}))

        # Self-signed JWK in header
        if "jwk" in header:
            findings.append(_finding(scanner, request, "jwt-self-signed-jwk",
                "Server Accepts Tokens With Self-Signed JWK",
                "A JWT header contains a JWK key embed. The server may be using the embedded key to verify the signature.",
                Severity.CRITICAL,
                "Never use the JWK/JKU/KID header parameters to fetch the verification key. Use a fixed trusted key store.",
                base_url, "CWE-347",
                Confidence.LIKELY, {**jwt_ev, "detail": "JWT header contains embedded JWK"}))

        # Weak HMAC secret check (common known-weak secrets)
        if alg in ("HS256", "HS384", "HS512"):
            weak_secrets = ["secret", "password", "123456", "qwerty", "changeme", "jwt_secret", "supersecret"]
            try:
                payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)
                header_b64 = parts[0]
                payload_b64 = parts[1]
                sig_b64 = parts[2]
                sig_bytes = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))

                import hashlib
                hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
                hash_fn = hash_map.get(alg, hashlib.sha256)

                for weak in weak_secrets:
                    expected = hmac.new(weak.encode(), f"{header_b64}.{payload_b64}".encode(), hash_fn).digest()
                    if hmac.compare_digest(expected, sig_bytes):
                        findings.append(_finding(scanner, request, "jwt-weak-secret",
                            "JWT Authorization Token Has Weak Secret",
                            f"A JWT token found in the response was signed with the weak secret '{weak}'. Attackers can forge arbitrary tokens.",
                            Severity.CRITICAL,
                            "Replace the JWT secret with a cryptographically random value of at least 256 bits.",
                            base_url, "CWE-326",
                            Confidence.CONFIRMED,
                            {"check": "jwt-weak-secret", "url": base_url, "alg": alg,
                             "detail": f"HMAC signature verified with weak secret (redacted)"}))
                        break
            except Exception:
                pass

    return findings


# ── main entry point ──────────────────────────────────────────────────────────

def run_all_checks(
    scanner: BaseScanner,
    request: ScanRequest,
    base_url: str,
    home_resp: httpx.Response | None,
) -> list[NormalizedFinding]:
    """
    Run all targeted domain checks and return a list of NormalizedFindings.
    `home_resp` is the response from GET <base_url> (may be None on connection failure).
    """
    findings: list[NormalizedFinding] = []

    if home_resp:
        findings += check_hsts(scanner, request, base_url, home_resp)
        findings += check_csp(scanner, request, base_url, home_resp)
        findings += check_clickjacking(scanner, request, base_url, home_resp)
        findings += check_cookies(scanner, request, base_url, home_resp)
        findings += check_info_leak_headers(scanner, request, base_url, home_resp)
        findings += check_sri(scanner, request, base_url, home_resp)
        findings += check_reverse_tabnabbing(scanner, request, base_url, home_resp)
        findings += check_directory_listing(scanner, request, base_url, home_resp)
        findings += check_jwt_in_response(scanner, request, base_url, home_resp)

    findings += check_exposed_paths(scanner, request, base_url)
    findings += check_heartbleed(scanner, request, base_url)

    # De-duplicate by fingerprint (same check on same target)
    seen: set[str] = set()
    unique: list[NormalizedFinding] = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)

    return unique
