"""
Proof-based confirmation for DAST findings.

After ZAP/Nuclei flag a potential SQLi or XSS, these functions run targeted
specialist tools that attempt *exploitation* — if they succeed, the finding is
upgraded from POSSIBLE/LIKELY → CONFIRMED.  If they fail the finding is retained
at its original confidence (never downgraded).

Tools:
  - SQLMap  — confirm SQL injection by attempting to extract data via the parameter
  - Dalfox  — confirm reflected XSS by generating and verifying a PoC payload

Both fall back gracefully when the tool is not installed.
"""
from __future__ import annotations

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import Optional

from models import Confidence, NormalizedFinding


@dataclass
class ConfirmResult:
    confirmed: bool
    tool: str
    technique: str = ""
    payload: str = ""
    evidence: dict = field(default_factory=dict)


# ── SQL Injection ─────────────────────────────────────────────────────────────

# ZAP rule IDs that indicate SQL injection findings
SQLI_RULE_IDS: frozenset[str] = frozenset({
    "40018",  # SQL Injection
    "40019",  # SQL Injection - MySQL
    "40020",  # SQL Injection - Hypersonic SQL
    "40021",  # SQL Injection - Oracle
    "40022",  # SQL Injection - PostgreSQL
    "40023",  # SQL Injection - SQLite
    "40024",  # Generic Padding Oracle (SQLi variant)
    "40027",  # SQL Injection - MsSQL
    "40028",  # SQL Injection - SQLite (alternative)
})

# ZAP rule IDs that indicate XSS findings
XSS_RULE_IDS: frozenset[str] = frozenset({
    "40012",  # Cross Site Scripting (Reflected)
    "40014",  # Cross Site Scripting (Persistent)
    "40016",  # Cross Site Scripting (Persistent) - Prime
    "40017",  # Cross Site Scripting (Persistent) - Spider
})


def is_sqli_candidate(finding: NormalizedFinding) -> bool:
    """Return True if the finding is a SQL injection candidate worth confirming."""
    if finding.rule_id in SQLI_RULE_IDS:
        return True
    title_lower = finding.title.lower()
    return "sql" in title_lower and "injection" in title_lower


def is_xss_candidate(finding: NormalizedFinding) -> bool:
    """Return True if the finding is a reflected XSS candidate worth confirming."""
    if finding.rule_id in XSS_RULE_IDS:
        return True
    title_lower = finding.title.lower()
    return "cross site scripting" in title_lower and "reflected" in title_lower


def confirm_sqli(
    url: str,
    param: Optional[str],
    auth_headers: dict[str, str],
    workspace: str,
    timeout: int = 75,
) -> ConfirmResult:
    """
    Run SQLMap against a specific URL/parameter to confirm SQL injection.

    Uses --level=2 --risk=1 (safe — no destructive payloads, no stacked queries)
    and --flush-session so it doesn't reuse a previous inconclusive result.

    Returns ConfirmResult.confirmed=True only when SQLMap explicitly identifies
    an injectable parameter (not just a "heuristic" hit).
    """
    sqli_dir = os.path.join(workspace, "sqlmap")
    os.makedirs(sqli_dir, exist_ok=True)

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",              # non-interactive — default answer to all prompts
        "--level=2",            # test GET/POST params + User-Agent/Referer
        "--risk=1",             # only safe tests — no UPDATE/DELETE payloads
        "--output-dir", sqli_dir,
        "--flush-session",      # fresh result every run
        "-q",                   # quiet — suppress progress noise
        "--no-logging",         # don't create per-target log files
        "--skip-heuristics",    # we already know the URL is suspicious
        "--technique=BEUST",    # all common techniques except time-based (too slow)
        "--time-sec=3",         # if T technique is tried, cap delay
    ]

    if param:
        cmd += ["-p", param]

    # Pass auth headers (-H can be specified multiple times)
    for hdr_name, hdr_value in auth_headers.items():
        cmd += ["--headers", f"{hdr_name}: {hdr_value}"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout_lower = (result.stdout or "").lower()

        # SQLMap confirmed indicator phrases in stdout
        confirmed = (
            "injectable" in stdout_lower
            or "sqlmap identified the following injection point" in stdout_lower
            or ("parameter" in stdout_lower and "is vulnerable" in stdout_lower)
        )

        # Extract technique + payload from output
        technique = ""
        payload_line = ""
        for line in (result.stdout or "").splitlines():
            ll = line.strip().lower()
            if ll.startswith("type:") and not technique:
                technique = line.strip()
            if ll.startswith("payload:") and not payload_line:
                payload_line = line.strip()[:200]

        return ConfirmResult(
            confirmed=confirmed,
            tool="sqlmap",
            technique=technique,
            payload=payload_line,
            evidence={
                "url": url,
                "param": param or "",
                "sqlmap_summary": (result.stdout or "")[-600:],
            },
        )

    except subprocess.TimeoutExpired:
        print(f"[confirm] SQLMap timed out ({timeout}s) on {url}")
        return ConfirmResult(confirmed=False, tool="sqlmap",
                             evidence={"timeout": True, "url": url})
    except FileNotFoundError:
        print("[confirm] SQLMap not installed — skipping SQLi confirmation")
        return ConfirmResult(confirmed=False, tool="sqlmap",
                             evidence={"not_installed": True})
    except Exception as exc:
        print(f"[confirm] SQLMap error on {url}: {exc}")
        return ConfirmResult(confirmed=False, tool="sqlmap",
                             evidence={"error": str(exc)[:200], "url": url})


# ── Cross-Site Scripting ──────────────────────────────────────────────────────

def confirm_xss(
    url: str,
    param: Optional[str],
    auth_headers: dict[str, str],
    workspace: str,
    timeout: int = 50,
) -> ConfirmResult:
    """
    Run Dalfox against a specific URL/parameter to confirm reflected XSS.

    Dalfox generates PoC payloads and verifies they actually reflect in the
    response — a positive result means the XSS is exploitable, not just matched
    by a pattern.

    JSON output mode: each line is a JSON object with type G/V/R:
      V = Verified (confirmed exploitable)
      G = Generic (confirmed reflected, may need browser to execute)
      R = Reflected (raw reflection without encoding bypass)
    """
    cmd = [
        "dalfox",
        "url", url,
        "--silence",        # suppress banner + progress
        "--no-spinner",     # no terminal spinner
        "--format", "json", # structured output
        "--timeout", "8",   # per-request timeout (seconds)
        "--worker", "15",   # concurrent workers
        "--skip-mining-dom",  # skip DOM mining — faster for confirmation
        "--skip-mining-dict", # skip wordlist mutation — we know the param
    ]

    if param:
        cmd += ["--param", param]

    for hdr_name, hdr_value in auth_headers.items():
        cmd += ["--header", f"{hdr_name}: {hdr_value}"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        confirmed_payloads: list[dict] = []
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                # V=Verified (highest confidence), G=Generic, R=Reflected
                if item.get("type") in ("V", "G", "R"):
                    confirmed_payloads.append({
                        "type": item.get("type"),
                        "param": item.get("param", ""),
                        "payload": str(item.get("payload", ""))[:200],
                        "poc": str(item.get("poc", ""))[:300],
                    })
            except json.JSONDecodeError:
                pass

        confirmed = (
            len(confirmed_payloads) > 0
            or "[V]" in (result.stdout or "")
            or "PoC:" in (result.stdout or "")
        )

        return ConfirmResult(
            confirmed=confirmed,
            tool="dalfox",
            technique="Reflected XSS" if confirmed else "",
            payload=confirmed_payloads[0]["payload"] if confirmed_payloads else "",
            evidence={
                "url": url,
                "param": param or "",
                "confirmed_payloads": confirmed_payloads[:3],
                "dalfox_raw": (result.stdout or "")[-400:],
            },
        )

    except subprocess.TimeoutExpired:
        print(f"[confirm] Dalfox timed out ({timeout}s) on {url}")
        return ConfirmResult(confirmed=False, tool="dalfox",
                             evidence={"timeout": True, "url": url})
    except FileNotFoundError:
        print("[confirm] Dalfox not installed — skipping XSS confirmation")
        return ConfirmResult(confirmed=False, tool="dalfox",
                             evidence={"not_installed": True})
    except Exception as exc:
        print(f"[confirm] Dalfox error on {url}: {exc}")
        return ConfirmResult(confirmed=False, tool="dalfox",
                             evidence={"error": str(exc)[:200], "url": url})


# ── Parallel confirmation ─────────────────────────────────────────────────────

def run_confirmations(
    sqli_candidates: list[NormalizedFinding],
    xss_candidates: list[NormalizedFinding],
    auth_headers: dict[str, str],
    workspace: str,
    max_sqli: int = 2,
    max_xss: int = 2,
) -> None:
    """
    Run SQLMap and Dalfox confirmations in parallel (up to max_sqli + max_xss total).

    Mutates findings in-place: confirmed findings get their confidence upgraded to
    CONFIRMED and have confirmation evidence added to their evidence dict.

    Cap candidates to keep the total confirmation window bounded:
      max_sqli=2 @ 75s + max_xss=2 @ 50s ≈ 75s wall-time (parallel).
    """
    sqli_targets = sqli_candidates[:max_sqli]
    xss_targets = xss_candidates[:max_xss]

    if not sqli_targets and not xss_targets:
        return

    print(f"[confirm] Starting parallel confirmation: {len(sqli_targets)} SQLi, {len(xss_targets)} XSS")

    confirm_workspace = os.path.join(workspace, "confirm")
    os.makedirs(confirm_workspace, exist_ok=True)

    # Map future → (finding, tool)
    future_map: dict[Future, tuple[NormalizedFinding, str]] = {}

    with ThreadPoolExecutor(max_workers=max_sqli + max_xss) as pool:
        for finding in sqli_targets:
            url = (finding.evidence or {}).get("url", "")
            param = (finding.evidence or {}).get("param") or None
            if not url:
                continue
            future = pool.submit(confirm_sqli, url, param, auth_headers,
                                 confirm_workspace, 75)
            future_map[future] = (finding, "sqli")

        for finding in xss_targets:
            url = (finding.evidence or {}).get("url", "")
            param = (finding.evidence or {}).get("param") or None
            if not url:
                continue
            future = pool.submit(confirm_xss, url, param, auth_headers,
                                 confirm_workspace, 50)
            future_map[future] = (finding, "xss")

        for future in as_completed(future_map):
            finding, kind = future_map[future]
            try:
                result: ConfirmResult = future.result()
            except Exception as exc:
                print(f"[confirm] {kind} future error: {exc}")
                continue

            url = (finding.evidence or {}).get("url", "")
            if result.confirmed:
                finding.confidence = Confidence.CONFIRMED
                if finding.evidence is None:
                    finding.evidence = {}
                if kind == "sqli":
                    finding.evidence["sqlmap_confirmed"] = True
                    finding.evidence["sqli_technique"] = result.technique
                    finding.evidence["sqli_payload"] = result.payload
                    print(f"[confirm] ✓ SQLi CONFIRMED at {url}")
                else:
                    finding.evidence["dalfox_confirmed"] = True
                    finding.evidence["xss_payload"] = result.payload
                    print(f"[confirm] ✓ XSS CONFIRMED at {url}")
            else:
                print(f"[confirm] ✗ {kind.upper()} not confirmed at {url} "
                      f"— keeping {finding.confidence}")
