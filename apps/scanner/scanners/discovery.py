"""
Content discovery and web server scanning for DAST accuracy.

Two complementary tools surface endpoints and server-level findings that ZAP
alone often misses:

  ffuf  — fast HTTP fuzzer / directory brute-forcer.  Discovers hidden paths,
           admin panels, backup files, and API endpoints before ZAP's spider
           starts, giving the active scanner a richer attack surface.

  Nikto — Perl-based web server vulnerability scanner.  Checks for dangerous
           default files, outdated software with known CVEs, HTTP method issues,
           and dozens of server misconfiguration classes beyond ZAP's scope.

Both fall back gracefully when the binary is not installed.
"""
from __future__ import annotations

import json
import os
import subprocess
import re
from typing import Optional
from urllib.parse import urlparse

from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


# ── ffuf ─────────────────────────────────────────────────────────────────────

# Wordlist search order — first match wins.
# dirb is installed in the scanner image via apt.
_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# Fallback compact wordlist embedded in code — highest-signal paths
_PRIORITY_PATHS = [
    "admin", "administrator", "login", "signin", "logout",
    "api", "api/v1", "api/v2", "api/v3", "graphql",
    "dashboard", "console", "panel", "manager", "management",
    "config", "configuration", "setup", "install",
    "phpinfo.php", "info.php", "test.php",
    ".env", ".env.local", ".env.production", ".env.dev",
    ".git", ".git/config", ".svn", ".htaccess", ".htpasswd",
    "backup", "backup.zip", "backup.sql", "db.sql", "database.sql",
    "dump.sql", "site.sql",
    "wp-admin", "wp-login.php", "wp-config.php",
    "phpmyadmin", "pma", "adminer.php", "adminer",
    "swagger", "swagger-ui", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml", "api-docs", "api/docs",
    "actuator", "actuator/health", "actuator/env",
    "actuator/mappings", "actuator/beans",
    "health", "healthz", "metrics", "status", "debug", "trace", "ping",
    "jenkins", "grafana", "kibana", "sonar", "nexus",
    "server-status", "server-info",
    ".DS_Store", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "web.config", "WEB-INF/web.xml",
    "README.md", "CHANGELOG.md", "package.json",
]


def _find_wordlist() -> Optional[str]:
    """Return the first available system wordlist path."""
    for path in _WORDLIST_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def run_ffuf(
    target_url: str,
    auth_headers: dict[str, str],
    workspace: str,
    timeout: int = 120,
) -> list[str]:
    """
    Brute-force common paths on the target to discover hidden endpoints.

    Returns a list of URLs that responded with actionable HTTP status codes
    (2xx, 3xx, 401, 403, 405).  These are seeded into ZAP so the active scanner
    covers them even if the spider didn't crawl them.

    Tries the system wordlist if available; falls back to the embedded priority
    list otherwise.  Gracefully returns [] if ffuf is not installed.
    """
    output_file = os.path.join(workspace, "ffuf_results.json")
    wordlist = _find_wordlist()

    if wordlist:
        wl_path = wordlist
        threads = "50"
    else:
        # Write the embedded priority list to a temp file
        wl_path = os.path.join(workspace, "priority_wordlist.txt")
        with open(wl_path, "w") as f:
            f.write("\n".join(_PRIORITY_PATHS))
        threads = "30"

    cmd = [
        "ffuf",
        "-u", f"{target_url.rstrip('/')}/FUZZ",
        "-w", wl_path,
        "-o", output_file,
        "-of", "json",
        "-mc", "200,204,301,302,307,401,403,405",   # meaningful response codes
        "-t", threads,
        "-timeout", "5",        # per-request timeout
        "-silent",
        "-noninteractive",
        "-maxtime", str(timeout - 5),  # give Python a 5s buffer
    ]

    # Inject auth headers
    for hdr_name, hdr_value in auth_headers.items():
        cmd += ["-H", f"{hdr_name}: {hdr_value}"]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        if not os.path.exists(output_file):
            return []

        with open(output_file) as f:
            data = json.load(f)

        discovered: list[str] = []
        for item in data.get("results", []):
            url = item.get("url", "")
            status = item.get("status", 0)
            if url and status > 0:
                discovered.append(url)

        print(f"[discovery] ffuf: {len(discovered)} paths discovered")
        return discovered

    except subprocess.TimeoutExpired:
        print("[discovery] ffuf timed out — continuing with ZAP-only coverage")
        return []
    except FileNotFoundError:
        print("[discovery] ffuf not installed — skipping content discovery")
        return []
    except Exception as exc:
        print(f"[discovery] ffuf error: {exc}")
        return []


# ── Nikto ────────────────────────────────────────────────────────────────────

def _nikto_severity(msg: str) -> Severity:
    """Map a Nikto finding message to a severity level by keyword."""
    m = msg.lower()
    if any(k in m for k in ["remote code", "rce", "arbitrary code", "exploit", "backdoor",
                              "critical", "shell upload"]):
        return Severity.CRITICAL
    if any(k in m for k in ["sql injection", "xss", "cross-site", "path traversal",
                              "directory traversal", "file inclusion", "upload allowed",
                              "default password", "dangerous file"]):
        return Severity.HIGH
    if any(k in m for k in ["admin interface", "phpinfo", "phpmyadmin", "adminer",
                              "outdated", "vulnerable version", "old version",
                              "default file", "test file", "backup file", ".git",
                              ".env", "config exposed"]):
        return Severity.MEDIUM
    if any(k in m for k in ["cookie", "header", "missing", "disclosure",
                              "information leak", "debug"]):
        return Severity.LOW
    return Severity.INFO


def run_nikto(
    scanner: BaseScanner,
    request: ScanRequest,
    target_url: str,
    auth_headers: dict[str, str],
    workspace: str,
    timeout: int = 180,
) -> list[NormalizedFinding]:
    """
    Run Nikto web server vulnerability scanner against the target.

    Nikto covers:
    - Outdated server software with published CVEs
    - Dangerous default files (CGI scripts, admin pages, backup files)
    - HTTP method issues (TRACE, PUT, DELETE)
    - Server misconfiguration (directory listing, version disclosure)
    - Known vulnerable web applications and components

    Supports both modern JSON output and legacy line-based text output,
    since Nikto's JSON format varies across versions.
    """
    json_output = os.path.join(workspace, "nikto_results.json")
    txt_output  = os.path.join(workspace, "nikto_results.txt")

    # Parse the target URL to extract host, port, SSL flag
    try:
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
        ssl_flag = ["-ssl"] if parsed.scheme == "https" else []
    except Exception:
        host = target_url
        port = "80"
        ssl_flag = []

    # Nikto with JSON output (modern versions)
    cmd = [
        "nikto",
        "-h", host,
        "-port", port,
        *ssl_flag,
        "-Format", "json",
        "-o", json_output,
        "-maxtime", str(max(timeout - 15, 30)),  # give Python a buffer
        "-nointeractive",
        "-nocolor",
        "-timeout", "5",
        "-nolookup",        # skip DNS reverse lookups — saves time
        "-Cgidirs", "all",  # check all CGI dirs
    ]

    # Cookie auth
    cookie = auth_headers.get("Cookie", "")
    if cookie:
        cmd += ["-cookies", cookie]

    findings: list[NormalizedFinding] = []

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        findings = _parse_nikto_json(scanner, request, target_url, json_output)
    except subprocess.TimeoutExpired:
        print("[discovery] Nikto timed out — collecting partial results")
        if os.path.exists(json_output):
            try:
                findings = _parse_nikto_json(scanner, request, target_url, json_output)
            except Exception:
                pass
    except FileNotFoundError:
        print("[discovery] Nikto not installed — skipping web server scan")
        return []
    except Exception as exc:
        print(f"[discovery] Nikto error: {exc}")

    # Fallback: if JSON parse yielded nothing, try text output
    if not findings:
        try:
            cmd_txt = [
                "nikto",
                "-h", host, "-port", port,
                *ssl_flag,
                "-o", txt_output,
                "-maxtime", str(max(timeout - 15, 30)),
                "-nointeractive", "-nocolor", "-timeout", "5", "-nolookup",
            ]
            if cookie:
                cmd_txt += ["-cookies", cookie]
            subprocess.run(cmd_txt, capture_output=True, text=True, timeout=timeout)
            if os.path.exists(txt_output):
                findings = _parse_nikto_text(scanner, request, target_url, txt_output)
        except Exception as exc:
            print(f"[discovery] Nikto text fallback error: {exc}")

    # De-duplicate by fingerprint
    seen: set[str] = set()
    unique: list[NormalizedFinding] = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)

    print(f"[discovery] Nikto: {len(unique)} findings")
    return unique


def _parse_nikto_json(
    scanner: BaseScanner,
    request: ScanRequest,
    target_url: str,
    output_file: str,
) -> list[NormalizedFinding]:
    """Parse Nikto JSON output into NormalizedFindings."""
    if not os.path.exists(output_file):
        return []

    with open(output_file) as f:
        content = f.read().strip()
    if not content:
        return []

    # Nikto JSON can be a single object or an array of host objects
    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        return []

    # Normalise to a list of host records
    if isinstance(raw, dict):
        records = [raw]
    elif isinstance(raw, list):
        records = raw
    else:
        return []

    findings: list[NormalizedFinding] = []

    for record in records:
        # Some versions nest under "host", others put vulnerabilities at top level
        vulnerabilities = (
            record.get("vulnerabilities")
            or record.get("host", {}).get("vulnerabilities", [])
            or []
        )

        for vuln in vulnerabilities:
            msg = vuln.get("msg") or vuln.get("message") or vuln.get("description", "")
            if not msg:
                continue

            osvdb = str(vuln.get("OSVDB") or vuln.get("osvdb") or "0")
            method = vuln.get("method", "GET")
            url = vuln.get("url") or vuln.get("uri") or target_url

            if url.startswith("/"):
                url = target_url.rstrip("/") + url

            rule_id = f"nikto:{osvdb}" if osvdb and osvdb != "0" else f"nikto:{abs(hash(msg)) % 999999}"
            severity = _nikto_severity(msg)

            fingerprint = scanner.compute_fingerprint(
                request.org_id, request.target_id, ScanType.DAST,
                rule_id, url, None,
            )

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=rule_id,
                title=msg[:120].strip(),
                description=msg.strip(),
                severity=severity,
                scan_type=ScanType.DAST,
                scanner="nikto",
                cwe_id=None,
                remediation=(
                    "Review the Nikto finding and apply the recommended remediation. "
                    "Consult https://cwe.mitre.org/ for the associated weakness class."
                ),
                references=[f"https://osvdb.org/{osvdb}"] if osvdb and osvdb != "0" else [],
                raw_output=vuln,
                confidence=Confidence.LIKELY,
                evidence={
                    "url": url,
                    "method": method,
                    "osvdb": osvdb,
                    "nikto_msg": msg,
                },
            ))

    return findings


def _parse_nikto_text(
    scanner: BaseScanner,
    request: ScanRequest,
    target_url: str,
    output_file: str,
) -> list[NormalizedFinding]:
    """
    Parse Nikto plain-text output as a fallback.

    Nikto text format:
        + OSVDB-3233: /path: Description of the finding
        + /path: Description without OSVDB ID
    """
    if not os.path.exists(output_file):
        return []

    findings: list[NormalizedFinding] = []
    osvdb_re = re.compile(r"^\+\s+(?:OSVDB-(\d+):\s+)?(/[^:]*)?:?\s+(.+)$")

    with open(output_file) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("+"):
                continue
            # Strip leading "+ "
            body = line.lstrip("+ ").strip()
            if body.startswith("Target IP") or body.startswith("Target Hostname"):
                continue

            m = osvdb_re.match(line)
            osvdb = m.group(1) if m and m.group(1) else "0"
            path  = m.group(2) if m and m.group(2) else ""
            msg   = m.group(3) if m and m.group(3) else body

            if not msg:
                continue

            url = target_url.rstrip("/") + path if path else target_url
            rule_id  = f"nikto:{osvdb}" if osvdb != "0" else f"nikto:{abs(hash(msg)) % 999999}"
            severity = _nikto_severity(msg)

            fingerprint = scanner.compute_fingerprint(
                request.org_id, request.target_id, ScanType.DAST,
                rule_id, url, None,
            )

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=rule_id,
                title=msg[:120].strip(),
                description=msg.strip(),
                severity=severity,
                scan_type=ScanType.DAST,
                scanner="nikto",
                cwe_id=None,
                remediation=(
                    "Review the Nikto finding and apply the recommended remediation."
                ),
                references=[f"https://osvdb.org/{osvdb}"] if osvdb != "0" else [],
                raw_output={"nikto_line": line, "osvdb": osvdb, "url": url, "msg": msg},
                confidence=Confidence.LIKELY,
                evidence={
                    "url": url,
                    "osvdb": osvdb,
                    "nikto_msg": msg,
                },
            ))

    return findings
