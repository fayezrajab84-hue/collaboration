from __future__ import annotations
import json
import subprocess
import time

import httpx

from config import settings
from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner
from .dast_checks import run_all_checks
from .confirm import is_sqli_candidate, is_xss_candidate, run_confirmations
from .discovery import run_ffuf, run_nikto

# ZAP confidence string → our Confidence enum
ZAP_CONFIDENCE_MAP: dict[str, Confidence] = {
    "Confirmed":       Confidence.CONFIRMED,
    "User Confirmed":  Confidence.CONFIRMED,
    "High":            Confidence.LIKELY,
    "Medium":          Confidence.POSSIBLE,
    "Low":             Confidence.POSSIBLE,
    "False Positive":  Confidence.POSSIBLE,   # kept only if ZAP didn't filter it out
}


ZAP_SEVERITY_MAP = {
    # ZAP returns risk as a human-readable string in modern versions
    "High":          Severity.HIGH,
    "Medium":        Severity.MEDIUM,
    "Low":           Severity.LOW,
    "Informational": Severity.INFO,
    # Legacy integer riskcode fallback (older ZAP versions)
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
    3: Severity.HIGH,
    2: Severity.MEDIUM,
    1: Severity.LOW,
    0: Severity.INFO,
}

# ZAP active-scan rules known to hang indefinitely (browser-based / slow fuzzing).
# Disabling these prevents scans from getting stuck at 50% forever.
DISABLED_ASCAN_RULES = [
    "40026",   # DOM XSS — launches headless browser, hangs on most targets
    "40025",   # Proxy Disclosure — recursive crawl, very slow
    "20019",   # External Redirect — overly broad fuzzing
    "40003",   # CRLF Injection — can hang on some hosts
]

# Cap active scan so it never runs longer than this (minutes).
ASCAN_MAX_DURATION_MINS = 7

# ── False-positive suppression ────────────────────────────────────────────────
# ZAP passive rules that produce near-zero actionable signal in practice.
# These are purely header/informational checks that are almost always noise:
# • Developers intentionally omit many of these headers on internal apps
# • They trigger on every page, flooding findings with duplicates
# • Security frameworks (CSP, HSTS, Permissions-Policy) already cover the risk
#
# Alerts with these IDs are DROPPED completely regardless of confidence.
ZAP_SUPPRESSED_RULE_IDS: set[str] = {
    "10049",   # Non-Storable Content
    "10050",   # Retrieved from Cache
    "10096",   # Timestamp Disclosure — Unix timestamps are not vulnerabilities
    "10097",   # Hash Disclosure — a hash alone is not a vulnerability
    "10109",   # Modern Web Application — purely informational marker
    "10110",   # Dangerous JS Functions — too many FPs in minified/bundled JS
    "10025",   # Sensitive Info in HTTP Referrer — almost always FP
    "10105",   # Weak Authentication Method — detects Basic Auth on every page
}

# Rules whose reported severity is downgraded to INFO (header best-practice advice,
# not exploitable vulnerabilities).  Still surfaced so devs can track them.
ZAP_DOWNGRADE_TO_INFO_IDS: set[str] = {
    "10015",   # Incomplete Cache-control Header
    "10020",   # X-Frame-Options Header
    "10021",   # X-Content-Type-Options Header Not Set
    "10035",   # Strict-Transport-Security Header Not Set
    "10037",   # X-Powered-By Header Leaks Server Info
    "10038",   # Content Security Policy Header Not Set
    "10054",   # Cookie Without SameSite Attribute
    "10063",   # Permissions Policy Header Not Set
    "10055",   # CSP: Policy Weaknesses
    "10061",   # X-AspNet-Version Response Header
    "10094",   # Base64 Disclosure — base64 is encoding, not encryption
    "10056",   # X-Debug-Token Information Leak (severity can be FP)
}

# Minimum confidence required to surface a finding at each severity level.
# Findings that don't meet the bar are dropped.
#   CRITICAL / HIGH  → always surface (even Low confidence)
#   MEDIUM           → require at least Possible (Medium ZAP confidence)
#   LOW              → require at least Likely (High ZAP confidence)
#   INFO             → require Confirmed (only proven informational findings)
_ZAP_CONFIDENCE_ORDER = {
    Confidence.POSSIBLE:   0,
    Confidence.LIKELY:     1,
    Confidence.CONFIRMED:  2,
}

_ZAP_MIN_CONFIDENCE: dict[Severity, Confidence] = {
    Severity.CRITICAL: Confidence.POSSIBLE,
    Severity.HIGH:     Confidence.POSSIBLE,
    Severity.MEDIUM:   Confidence.POSSIBLE,
    Severity.LOW:      Confidence.LIKELY,
    Severity.INFO:     Confidence.CONFIRMED,
}


def _zap_should_include(alert_id: str, severity: Severity, confidence: Confidence) -> bool:
    """Return False if the ZAP alert should be suppressed as a false positive."""
    # 1. Hard-suppressed rules — always drop
    if alert_id in ZAP_SUPPRESSED_RULE_IDS:
        return False
    # 2. Confidence × severity gate
    required = _ZAP_MIN_CONFIDENCE.get(severity, Confidence.POSSIBLE)
    actual_order   = _ZAP_CONFIDENCE_ORDER.get(confidence, 0)
    required_order = _ZAP_CONFIDENCE_ORDER.get(required, 0)
    if actual_order < required_order:
        return False
    return True


class DASTScanner(BaseScanner):
    """DAST scanner using OWASP ZAP REST API."""

    def __init__(self):
        self.zap_url = settings.zap_base_url
        self.api_key = settings.zap_api_key

    # ── Progress callback ─────────────────────────────────────────────────────

    def _report_progress(self, request: ScanRequest, pct: int, phase: str) -> None:
        """POST phase progress to the API so it can emit an SSE event to the frontend."""
        if not request.api_url:
            return
        url = f"{request.api_url}/api/scans/{request.scan_job_id}/progress"
        try:
            with httpx.Client(timeout=5) as client:
                client.post(url, json={"pct": pct, "phase": phase})
        except Exception:
            pass  # progress callback failure is non-fatal

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_target_url(self, domain: str) -> str:
        """Return the first URL that responds (https preferred, then http)."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
                    resp = client.get(url)
                    if resp.status_code < 500:
                        return url
            except Exception:
                continue
        # Fall back to http if neither responds (ZAP will handle the error)
        return f"http://{domain}"

    def _zap(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.zap_url}{path}"
        p = {"apikey": self.api_key, **(params or {})}
        with httpx.Client(timeout=30) as client:
            res = client.get(url, params=p)
            res.raise_for_status()
            return res.json()

    def _configure_ascan(self) -> None:
        """Disable rules known to hang and cap total active-scan duration."""
        # Cap duration — ZAP will stop the scan gracefully and return whatever it found
        try:
            self._zap(
                "/JSON/ascan/action/setOptionMaxScanDurationInMins/",
                {"Integer": str(ASCAN_MAX_DURATION_MINS)},
            )
        except Exception as exc:
            print(f"[dast] Warning: could not set max scan duration: {exc}")

        # Disable rules that are known to hang
        for rule_id in DISABLED_ASCAN_RULES:
            try:
                self._zap(
                    "/JSON/ascan/action/disableScanners/",
                    {"ids": rule_id},
                )
            except Exception as exc:
                print(f"[dast] Warning: could not disable rule {rule_id}: {exc}")

    def _tune_ascan_policy(self) -> None:
        """
        Set HIGH attack strength for high-value vulnerability classes.

        ZAP's default strength is MEDIUM for all rules.  Upgrading SQLi and XSS
        rules to HIGH makes ZAP try more payloads and edge-case variants,
        increasing true-positive detection at the cost of slightly longer scan
        time for those rule families.

        Also ensures path traversal and SSTI rules run at HIGH — these have good
        FP rates and are commonly missed at MEDIUM strength.
        """
        # (rule_id, strength) pairs
        HIGH_STRENGTH_RULES = [
            # SQL injection family — all backend types
            "40018",  # SQL Injection (generic)
            "40019",  # SQL Injection - MySQL
            "40020",  # SQL Injection - Hypersonic SQL
            "40021",  # SQL Injection - Oracle
            "40022",  # SQL Injection - PostgreSQL
            "40023",  # SQL Injection - SQLite
            "40027",  # SQL Injection - MsSQL
            # Cross-Site Scripting
            "40012",  # Cross Site Scripting (Reflected)
            "40014",  # Cross Site Scripting (Persistent)
            "40016",  # Cross Site Scripting (Persistent) - Prime
            "40017",  # Cross Site Scripting (Persistent) - Spider
            # Path traversal / RFI — commonly missed at MEDIUM
            "6",      # Path Traversal
            "7",      # Remote File Inclusion
            # Server-Side Template Injection
            "90035",  # Server Side Template Injection
        ]
        upgraded = 0
        for rule_id in HIGH_STRENGTH_RULES:
            try:
                self._zap(
                    "/JSON/ascan/action/setScannerAttackStrength/",
                    {"id": rule_id, "attackStrength": "HIGH"},
                )
                upgraded += 1
            except Exception:
                pass   # non-fatal — rule may not exist in this ZAP version
        if upgraded:
            print(f"[dast] Policy tuned: {upgraded} rules upgraded to HIGH attack strength")

    # ── Authentication setup ──────────────────────────────────────────────────

    def _setup_auth_context(self, request: ScanRequest, target_url: str) -> tuple[str | None, str | None]:
        """Configure a ZAP authentication context when auth_config is provided.

        Returns (context_id, user_id) if auth was set up, (None, None) otherwise.
        """
        from models import AuthType
        auth = request.auth_config
        if not auth:
            return None, None

        try:
            if auth.auth_type == AuthType.HEADER or auth.auth_type == AuthType.COOKIE:
                # Inject a static header/cookie into every ZAP request via the replacer
                name  = auth.header_name or "Authorization"
                value = auth.header_value or ""
                self._zap("/JSON/replacer/action/addRule/", {
                    "description": "auth-injection",
                    "enabled":     "true",
                    "matchType":   "REQ_HEADER",
                    "matchRegex":  "false",
                    "matchString": name,
                    "replacement": value,
                    "initiators":  "",
                })
                print(f"[dast] Header auth configured: {name}")
                return None, None   # no ZAP context needed for header injection

            # ── FORM-based authentication ──────────────────────────────────
            if not auth.login_url or not auth.username or not auth.password:
                print("[dast] FORM auth skipped — missing loginUrl, username, or password")
                return None, None

            # Resolve the login URL (absolute or path relative to target)
            login_url = (
                auth.login_url if auth.login_url.startswith("http")
                else target_url.rstrip("/") + "/" + auth.login_url.lstrip("/")
            )

            # 1. Create a context that covers the whole target
            ctx_resp = self._zap("/JSON/context/action/newContext/", {"contextName": f"auth-ctx-{request.scan_job_id}"})
            ctx_id   = ctx_resp.get("contextId", "1")
            self._zap("/JSON/context/action/includeInContext/", {
                "contextName": f"auth-ctx-{request.scan_job_id}",
                "regex": f"{target_url}.*",
            })

            # 2. Configure form-based authentication
            login_data = (
                f"{auth.username_field}=%7B%25username%25%7D"
                f"&{auth.password_field}=%7B%25password%25%7D"
            )
            self._zap("/JSON/authentication/action/setAuthenticationMethod/", {
                "contextId":            ctx_id,
                "authMethodName":       "formBasedAuthentication",
                "authMethodConfigParams":
                    f"loginUrl={login_url}&loginRequestData={login_data}",
            })

            # 3. Logged-in / logged-out indicators so ZAP can detect session expiry
            self._zap("/JSON/authentication/action/setLoggedInIndicator/", {
                "contextId":            ctx_id,
                "loggedInIndicatorRegex": auth.logged_in_pattern,
            })
            self._zap("/JSON/authentication/action/setLoggedOutIndicator/", {
                "contextId":            ctx_id,
                "loggedOutIndicatorRegex": auth.logged_out_pattern,
            })

            # 4. Create a ZAP user with the supplied credentials
            user_resp = self._zap("/JSON/users/action/newUser/", {
                "contextId": ctx_id,
                "name":      "scanner-user",
            })
            user_id = user_resp.get("userId", "0")
            self._zap("/JSON/users/action/setAuthenticationCredentials/", {
                "contextId":      ctx_id,
                "userId":         user_id,
                "authCredentialsConfigParams":
                    f"username={auth.username}&password={auth.password}",
            })
            self._zap("/JSON/users/action/setUserEnabled/", {
                "contextId": ctx_id,
                "userId":    user_id,
                "enabled":   "true",
            })

            # 5. Force ZAP to use this user for all requests
            self._zap("/JSON/forcedUser/action/setForcedUser/", {
                "contextId": ctx_id,
                "userId":    user_id,
            })
            self._zap("/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "true"})

            print(f"[dast] Form auth configured for {login_url} (user: {auth.username})")
            return ctx_id, user_id

        except Exception as exc:
            print(f"[dast] Warning: auth setup failed — running unauthenticated: {exc}")
            return None, None

    def _teardown_auth(self, ctx_id: str | None) -> None:
        """Disable forced-user mode and clean up the context after scanning."""
        try:
            self._zap("/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "false"})
        except Exception:
            pass
        # Clean up replacer rules added for header/cookie auth
        try:
            rules = self._zap("/JSON/replacer/view/rules/").get("rules", [])
            for rule in rules:
                if rule.get("description", "").startswith("auth-injection"):
                    self._zap("/JSON/replacer/action/removeRule/", {"description": rule["description"]})
        except Exception:
            pass

    def _katana_crawl(self, target_url: str, workspace: str) -> list[str]:
        """
        Crawl the target with Katana (headless JS-aware) and return discovered URLs.
        Falls back to empty list if Katana is not installed or times out.
        """
        import os
        output_file = os.path.join(workspace, "katana_urls.txt")
        try:
            subprocess.run(
                [
                    "katana",
                    "-u", target_url,
                    "-d", "3",           # depth
                    "-jc",               # JS crawling (headless)
                    "-kf", "all",        # known files (robots.txt, sitemap, etc.)
                    "-silent",
                    "-o", output_file,
                    "-timeout", "30",
                    "-c", "10",          # concurrency
                    "-rl", "50",         # rate limit req/s
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if not os.path.exists(output_file):
                return []
            with open(output_file) as f:
                urls = [line.strip() for line in f if line.strip().startswith("http")]
            print(f"[dast] Katana discovered {len(urls)} URLs")
            return urls[:500]  # cap to avoid overwhelming ZAP
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[dast] Katana not available or timed out — using ZAP spider only")
            return []
        except Exception as exc:
            print(f"[dast] Katana error: {exc}")
            return []

    # ── Playwright SPA crawl ──────────────────────────────────────────────────

    def _playwright_crawl(self, target_url: str, request: ScanRequest, workspace: str) -> list[str]:
        """
        Crawl the target with a real headless Chromium browser (Playwright).

        Unlike Katana, Playwright executes JavaScript fully:
          - Follows client-side routing (React Router, Vue Router, Angular Router)
          - Intercepts every XHR / fetch call made by the SPA → discovers hidden API endpoints
          - Handles lazy-loaded content and dynamic navigation
          - Respects auth headers so authenticated pages are crawled

        Returns up to 500 unique in-scope URLs collected from:
          1. Navigation events (page.goto, clicks that change the URL)
          2. Network requests intercepted during page execution

        Falls back gracefully to [] if Playwright / Chromium are not available.
        """
        import os as _os
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            print("[dast] Playwright not installed — skipping SPA crawl")
            return []

        # Derive the scope origin so we only collect in-scope URLs
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            scope_origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            scope_origin = target_url

        discovered: set[str] = set()
        MAX_URLS   = 500
        NAV_DEPTH  = 2          # how many SPA-link clicks to follow
        PAGE_TIMEOUT = 15_000   # ms

        auth_headers = self.auth_header_dict(request.auth_config, request.session_cookie)

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",          # allow cross-origin requests to be captured
                        "--ignore-certificate-errors",
                    ],
                )
                context = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800},
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
                        "DevSecOps-Scanner/1.0"
                    ),
                    extra_http_headers=auth_headers,
                )

                def _on_request(req) -> None:
                    """Intercept every network request and collect in-scope URLs."""
                    url = req.url.split("?")[0].rstrip("/")   # strip query + trailing slash
                    if url.startswith(scope_origin) and len(discovered) < MAX_URLS:
                        discovered.add(url)

                page = context.new_page()
                page.on("request", _on_request)

                # ── Phase 1: load the entry point ─────────────────────────────
                try:
                    page.goto(target_url, timeout=PAGE_TIMEOUT, wait_until="networkidle")
                except PWTimeout:
                    pass   # page may have loaded enough even on timeout
                except Exception as exc:
                    print(f"[dast] Playwright: goto {target_url} failed: {exc}")

                # ── Phase 2: click visible in-scope links to trigger SPA routing ──
                for _depth in range(NAV_DEPTH):
                    if len(discovered) >= MAX_URLS:
                        break
                    try:
                        # Collect all <a> hrefs that are same-origin
                        hrefs: list[str] = page.eval_on_selector_all(
                            "a[href]",
                            """els => els
                                .map(e => e.href)
                                .filter(h => h && !h.startsWith('javascript') && !h.startsWith('mailto'))
                            """,
                        )
                    except Exception:
                        hrefs = []

                    for href in hrefs[:30]:   # cap per-depth to avoid runaway clicks
                        if len(discovered) >= MAX_URLS:
                            break
                        href_clean = href.split("?")[0].rstrip("/")
                        if not href_clean.startswith(scope_origin):
                            continue
                        if href_clean in discovered:
                            continue
                        try:
                            page.goto(href, timeout=PAGE_TIMEOUT, wait_until="networkidle")
                        except PWTimeout:
                            pass
                        except Exception:
                            pass

                browser.close()

        except Exception as exc:
            print(f"[dast] Playwright crawl error: {exc}")

        urls = list(discovered)
        print(f"[dast] Playwright SPA crawl: {len(urls)} in-scope URLs discovered")
        return urls[:MAX_URLS]

    # ── Nuclei API scan (OpenAPI spec endpoints) ──────────────────────────────

    def _nuclei_api_scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        """
        Run Nuclei against the URLs extracted from the imported OpenAPI/Swagger spec.
        Focuses on API-specific vulnerability classes: auth bypass, injection,
        sensitive data exposure, misconfigs.
        """
        import os
        if not request.api_spec_urls:
            return []

        # Write URL list to a file for Nuclei -l flag
        url_list_path = os.path.join(workspace, "api_spec_urls.txt")
        with open(url_list_path, "w") as f:
            f.write("\n".join(request.api_spec_urls[:500]))

        cmd = [
            "nuclei",
            "-l", url_list_path,
            "-tags", "api,rest,graphql,jwt,auth,sqli,xss,ssrf,exposure,misconfig,token,idor",
            "-json", "-nc", "-silent",
            "-severity", "critical,high,medium,low",
            "-timeout", "10",
            "-retries", "1",
            "-bulk-size", "20",
        ]

        # Auth
        auth_headers = self.auth_header_dict(request.auth_config, request.session_cookie)
        for hdr_name, hdr_value in auth_headers.items():
            cmd += ["-H", f"{hdr_name}: {hdr_value}"]

        # OAST
        if settings.interactsh_url:
            cmd += ["-iserver", settings.interactsh_url]

        result = self.run_cmd(cmd, timeout=300)

        findings: list[NormalizedFinding] = []
        severity_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            template_id = item.get("template-id", "nuclei-api")
            info = item.get("info", {})
            matched_at = item.get("matched-at", "")
            severity = severity_map.get(info.get("severity", "info").lower(), Severity.INFO)
            fingerprint = self.compute_fingerprint(
                request.org_id, request.target_id, ScanType.DAST,
                f"nuclei-api:{template_id}:{matched_at}", matched_at, None
            )
            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=f"nuclei-api:{template_id}",
                title=info.get("name", template_id),
                description=info.get("description", f"Nuclei API scan: {template_id}"),
                severity=severity,
                scan_type=ScanType.DAST,
                scanner="nuclei-api",
                remediation=info.get("remediation"),
                references=info.get("reference", []),
                raw_output=item,
                confidence=Confidence.LIKELY,
                evidence={
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "curl_command": item.get("curl-command", "")[:500],
                },
            ))
        return findings

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.domain:
            raise ValueError("domain required for DAST scan")

        # Probe for http vs https — use the scheme that responds
        target_url = self._resolve_target_url(request.domain)
        self._report_progress(request, 2, "probing")

        # Fetch the home page once — reused by targeted checks later
        try:
            with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
                home_resp = client.get(target_url)
        except Exception:
            home_resp = None

        # Configure active scanner (disable known-hanging rules + cap duration)
        self._configure_ascan()
        # Upgrade attack strength for high-signal rule families
        self._tune_ascan_policy()

        # Configure authentication context (if credentials were provided)
        ctx_id, user_id = self._setup_auth_context(request, target_url)
        authenticated = ctx_id is not None or (
            request.auth_config is not None and
            request.auth_config.auth_type.value in ("HEADER", "COOKIE")
        )
        if authenticated:
            self._report_progress(request, 4, "auth_configured")

        # 0.5. Pre-crawl with Playwright + Katana + ffuf to seed ZAP's scope
        import os as _os
        crawl_workspace = _os.path.join(workspace, "crawl")
        _os.makedirs(crawl_workspace, exist_ok=True)

        # Build auth headers for external tools (ffuf, SQLMap, Dalfox)
        auth_headers_for_tools = self.auth_header_dict(request.auth_config, None)

        # Playwright: intercepts real XHR/fetch calls from JS frameworks — best for SPAs
        playwright_urls = self._playwright_crawl(target_url, request, crawl_workspace)
        self._report_progress(request, 8, "playwright_crawl_done")

        # Katana: fast link-follower for traditional and semi-JS sites
        katana_urls = self._katana_crawl(target_url, crawl_workspace)
        self._report_progress(request, 12, "katana_crawl_done")

        # ffuf: brute-force common paths to expose hidden endpoints & admin panels
        ffuf_workspace = _os.path.join(workspace, "ffuf")
        _os.makedirs(ffuf_workspace, exist_ok=True)
        ffuf_urls = run_ffuf(target_url, auth_headers_for_tools, ffuf_workspace, timeout=90)
        self._report_progress(request, 14, "ffuf_discovery_done")
        if ffuf_urls:
            print(f"[dast] ffuf surfaced {len(ffuf_urls)} additional paths for ZAP")

        # Merge all discovery sources; de-duplicate preserving order
        seed_urls = list(dict.fromkeys(
            playwright_urls + katana_urls + ffuf_urls + list(request.api_spec_urls)
        ))
        if seed_urls:
            # Seed all discovered/spec URLs into ZAP so the active scanner covers them
            for su in seed_urls[:400]:
                try:
                    self._zap("/JSON/core/action/accessUrl/", {"url": su, "followRedirects": "false"})
                except Exception:
                    pass
            print(
                f"[dast] Seeded {len(playwright_urls)} Playwright + {len(katana_urls)} Katana + "
                f"{len(request.api_spec_urls)} OpenAPI-spec URLs into ZAP "
                f"({len(seed_urls)} unique)"
            )

        # 1. Spider the target (use authenticated spider when context is set up)
        if ctx_id and user_id:
            spider_resp = self._zap("/JSON/spider/action/scanAsUser/", {
                "contextId":   ctx_id,
                "userId":      user_id,
                "url":         target_url,
                "maxChildren": "10",
            })
        else:
            spider_resp = self._zap("/JSON/spider/action/scan/", {"url": target_url, "maxChildren": "10"})
        spider_id = spider_resp.get("scan", "0")
        self._report_progress(request, 15, "spider_started")

        # 2. Wait for spider to complete (max 5 min)
        for _ in range(60):
            status = self._zap("/JSON/spider/view/status/", {"scanId": spider_id})
            spider_pct = int(status.get("status", "0"))
            # Map spider 0–100 → overall 5–25
            self._report_progress(request, 5 + int(spider_pct * 0.20), "spidering")
            if spider_pct >= 100:
                break
            time.sleep(5)

        self._report_progress(request, 25, "spider_done")

        # 3. Start active scan (use context when authenticated)
        ascan_params: dict = {"url": target_url, "recurse": "true"}
        if ctx_id:
            ascan_params["contextId"] = ctx_id
        ascan_resp = self._zap("/JSON/ascan/action/scan/", ascan_params)
        ascan_id = ascan_resp.get("scan", "0")
        self._report_progress(request, 27, "active_scan_started")

        # 4. Poll until complete or ZAP's own duration cap kicks in
        #    Allow up to (ASCAN_MAX_DURATION_MINS + 2) minutes as a safety net
        max_polls = (ASCAN_MAX_DURATION_MINS + 2) * 12  # 12 polls/min (every 5 s)
        for _ in range(max_polls):
            status = self._zap("/JSON/ascan/view/status/", {"scanId": ascan_id})
            ascan_pct = int(status.get("status", "0"))
            # Map active scan 0–100 → overall 27–90
            self._report_progress(request, 27 + int(ascan_pct * 0.63), "active_scanning")
            if ascan_pct >= 100:
                break
            time.sleep(5)
        else:
            # Gracefully stop the scan so ZAP doesn't keep running in the background
            try:
                self._zap("/JSON/ascan/action/stop/", {"scanId": ascan_id})
            except Exception:
                pass
            print(f"[dast] Active scan timed out after {ASCAN_MAX_DURATION_MINS + 2} min — collecting partial results")

        self._teardown_auth(ctx_id)
        self._report_progress(request, 90, "active_scan_done")

        # 5. Collect alerts
        alerts_resp = self._zap("/JSON/core/view/alerts/", {"baseurl": target_url})
        alerts = alerts_resp.get("alerts", [])
        self._report_progress(request, 95, "collecting")

        findings: list[NormalizedFinding] = []
        suppressed_count = 0
        for alert in alerts:
            # Modern ZAP returns "risk" as a string ("High"/"Medium"/"Low"/"Informational").
            # Older versions used "riskcode" as an int (3/2/1/0). Support both.
            risk_code = alert.get("risk") or alert.get("riskcode", "0")
            alert_id = alert.get("alertRef", alert.get("pluginid",
                        alert.get("alert", "zap-alert")))
            url = alert.get("url", "")
            description = alert.get("description", "")
            solution = alert.get("solution", "")

            # ZAP confidence string (e.g. "High", "Confirmed", "Medium")
            zap_confidence_str = alert.get("confidence", "Medium")
            confidence = ZAP_CONFIDENCE_MAP.get(zap_confidence_str, Confidence.POSSIBLE)

            severity = ZAP_SEVERITY_MAP.get(risk_code, Severity.INFO)

            # Apply downgrade rules before FP filter
            if alert_id in ZAP_DOWNGRADE_TO_INFO_IDS:
                severity = Severity.INFO

            # ── False-positive gate ───────────────────────────────────────────
            if not _zap_should_include(alert_id, severity, confidence):
                suppressed_count += 1
                continue

            fingerprint = self.compute_fingerprint(
                request.org_id, request.target_id, ScanType.DAST,
                alert_id, url, None
            )

            # Build evidence from ZAP alert fields
            evidence: dict = {
                "url": url,
                "zap_confidence": zap_confidence_str,
                "response_status": alert.get("statusCode", ""),
            }
            if alert.get("evidence"):
                evidence["evidence"] = alert["evidence"]
            if alert.get("attack"):
                evidence["attack"] = alert["attack"]
            if alert.get("param"):
                evidence["param"] = alert["param"]
            if alert.get("other"):
                evidence["other"] = str(alert["other"])[:300]

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
                confidence=confidence,
                evidence=evidence,
            ))

        if suppressed_count:
            print(f"[dast] FP filter: suppressed {suppressed_count}/{len(alerts)} ZAP alerts "
                  f"(low-confidence informational noise)")

        # ── Proof-based confirmation for SQLi and XSS candidates ─────────────
        # Extract candidates before running Nuclei/Nikto so confirmation tools
        # run while those scans are executing (overlapping I/O).
        sqli_candidates = [f for f in findings if is_sqli_candidate(f)
                           and f.evidence and f.evidence.get("url")]
        xss_candidates  = [f for f in findings if is_xss_candidate(f)
                           and f.evidence and f.evidence.get("url")]

        if sqli_candidates or xss_candidates:
            print(f"[dast] Confirmation queue: {len(sqli_candidates)} SQLi, "
                  f"{len(xss_candidates)} XSS candidates")
            self._report_progress(request, 92, "confirming_findings")
            run_confirmations(
                sqli_candidates, xss_candidates,
                auth_headers_for_tools, workspace,
                max_sqli=2, max_xss=2,
            )

        # Run Nuclei against OpenAPI spec endpoints for fast API-specific checks
        if request.api_spec_urls:
            self._report_progress(request, 94, "nuclei_api_scan")
            nuclei_findings = self._nuclei_api_scan(request, workspace)
            findings += nuclei_findings
            print(f"[dast] Nuclei API scan: {len(nuclei_findings)} findings from {len(request.api_spec_urls)} spec endpoints")

        # Run targeted checks covering every item in the DOMAIN_CHECKS list
        self._report_progress(request, 96, "targeted_checks")
        targeted = run_all_checks(self, request, target_url, home_resp)
        findings += targeted

        # Run Nikto web server scanner — covers server-level misconfigs and
        # dangerous default files that ZAP's active scan often misses
        self._report_progress(request, 97, "nikto_scan")
        nikto_workspace = _os.path.join(workspace, "nikto")
        _os.makedirs(nikto_workspace, exist_ok=True)
        nikto_findings = run_nikto(
            self, request, target_url, auth_headers_for_tools,
            nikto_workspace, timeout=180,
        )
        findings += nikto_findings

        zap_count     = len(alerts) - suppressed_count
        nuclei_count  = len(findings) - zap_count - len(targeted) - len(nikto_findings)
        print(
            f"[dast] Summary — ZAP: {zap_count}  Nuclei API: {nuclei_count}  "
            f"Targeted: {len(targeted)}  Nikto: {len(nikto_findings)}  "
            f"Confirmed: {sum(1 for f in findings if f.confidence == Confidence.CONFIRMED)}"
        )

        self._report_progress(request, 99, "done")
        return findings
