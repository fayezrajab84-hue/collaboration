"""
CloudAzureScanner — Phase 29 Slice A.

Wraps Prowler 4.x for Azure CSPM evaluation. Same architectural pattern
as the existing scanner wrappers (Trivy → SCA, Semgrep → SAST, ZAP →
DAST, etc.):

  ScanRequest  →  set Azure SP env vars
              →  invoke `prowler azure --sp-env-auth ... -M json-ocsf`
              →  parse OCSF JSON output
              →  normalise to NormalizedFinding[]

Why Prowler:
  - 250+ Azure checks vs 25 hand-rolled rules
  - CIS / PCI / NIST / ISO / HIPAA / SOC2 / GDPR mappings ship for free
  - Maintained community project (Apache 2.0); MS publishes new resource
    types, Prowler ships checks
  - Native JSON output, OCSF-compliant — no scrape-and-pray HTML parsing
  - Consistent with the rest of the BreachLens scanner architecture
    (every other tier is an OSS-tool wrapper)

What we do NOT bake in (deliberate):
  - Hand-curated severity overrides — Prowler's defaults are the
    upstream consensus; any tweak should happen in a downstream
    suppressions / risk-score layer, not silently here.
  - Custom checks — would defeat the moat ("we use the open standard
    everyone else uses, plus correlation"). Add custom rules in the
    application layer or contribute upstream.

Failure modes handled:
  - Bad credentials       → Prowler exits non-zero with auth error in stderr.
                            We surface the stderr tail in the raised exception
                            so the ScanJob.error column reads cleanly.
  - Network unavailable   → same as above; classified by stderr text in worker.
  - Empty OCSF output     → no findings is valid (subscription is clean);
                            return [].
  - Prowler not installed → exec fails with FileNotFoundError; raised cleanly
                            so the worker can show "Prowler not installed in
                            scanner image — rebuild required".

Per-scan timeout:
  Prowler against a real subscription with hundreds of resources can take
  10-20 min. The API worker sets a 30-min timeout (1800s) for CLOUD
  scans, matching DAST. We don't impose an additional timeout here —
  the API timeout is the authority.
"""
from __future__ import annotations

import json
import os
from typing import Any

from models import NormalizedFinding, ScanRequest
from ..base import BaseScanner
from .normalizer import normalize_prowler_findings


# ── Constants ───────────────────────────────────────────────────────────

# Service whitelist — controls which Prowler check categories run. The
# default Prowler `azure` invocation runs ALL checks; we scope to the
# resource types operators most frequently care about for Slice A so
# scan time stays under ~10min on typical subscriptions. Adjusted in
# Commit 2B / Commit 3 as we expand cross-tier bridges.
#
# Empty list = run all services (Prowler default). Operators with strict
# scope can override via env (CSPM_AZURE_SERVICES) without a code change.
_DEFAULT_SERVICES: list[str] = []  # empty = all services


def _get_services() -> list[str]:
    raw = os.environ.get("CSPM_AZURE_SERVICES", "")
    if not raw.strip():
        return _DEFAULT_SERVICES
    return [s.strip() for s in raw.split(",") if s.strip()]


def _prowler_binary() -> str:
    """Resolve the prowler executable path.

    Prowler ships ~80 transitive Azure SDK + Pluggy + multi-cloud deps
    that conflict with the BreachLens scanner image's existing pinned
    deps (semgrep / checkov / playwright). pip's backtracking resolver
    enters a multi-hour loop trying to satisfy both. Solution: install
    Prowler in an ISOLATED venv so its dep tree stays separate from
    the scanner image's deps. The venv's ``bin/prowler`` is the entry
    point we invoke from here.

    Resolution order:
      1. ``PROWLER_BIN`` env var (operator override / Dockerfile)
      2. ``$HOME/prowler-venv/bin/prowler`` (BreachLens convention)
      3. ``/usr/local/bin/prowler`` (legacy / direct pip install)
      4. ``prowler`` on PATH (fallback)
    """
    override = os.environ.get("PROWLER_BIN")
    if override and os.path.exists(override):
        return override
    home = os.environ.get("HOME", "/home/scanner")
    venv_path = f"{home}/prowler-venv/bin/prowler"
    if os.path.exists(venv_path):
        return venv_path
    if os.path.exists("/usr/local/bin/prowler"):
        return "/usr/local/bin/prowler"
    return "prowler"


# ── Scanner class ───────────────────────────────────────────────────────

class CloudAzureScanner(BaseScanner):
    """Prowler-Azure wrapper. Activated when ScanRequest.scan_type == CLOUD
    and target_type == CLOUD_ACCOUNT. Requires cloud_credentials with
    Azure provider populated."""

    scanner_name = "prowler"

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        creds = request.cloud_credentials
        if creds is None:
            raise ValueError("CLOUD scan requires cloud_credentials")
        if creds.provider != "AZURE":
            raise ValueError(f"CLOUD scan unsupported provider: {creds.provider} (Slice A is AZURE-only)")
        for field in ("tenant_id", "client_id", "client_secret", "subscription_id"):
            if not getattr(creds, field):
                raise ValueError(f"Azure CLOUD scan missing required credential field: {field}")

        # Workspace layout:
        #   <workspace>/prowler-out/<filename>.ocsf.json   ← parsed
        #   <workspace>/prowler-out/<filename>.csv         ← bonus, ignored
        # Prowler creates the output directory itself but we mkdir to
        # surface permission errors early.
        output_dir = os.path.join(workspace, "prowler-out")
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"scan-{request.scan_job_id}"

        # SP credentials are passed via env vars — Prowler's `--sp-env-auth`
        # mode reads AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
        # from the environment. Putting them on the command line would
        # leak through ps/proc. The env dict is not logged.
        env = {
            "AZURE_TENANT_ID":        creds.tenant_id,
            "AZURE_CLIENT_ID":        creds.client_id,
            "AZURE_CLIENT_SECRET":    creds.client_secret,
            # AZURE_SUBSCRIPTION_IDS is what Prowler reads when --subscription-ids
            # is also passed (it cross-checks); set both to the same value.
            "AZURE_SUBSCRIPTION_IDS": creds.subscription_id,
        }

        cmd = [
            "prowler", "azure",
            "--sp-env-auth",
            "--subscription-ids", creds.subscription_id,
            "--output-modes", "json-ocsf",
            "--output-directory", output_dir,
            "--output-filename", output_filename,
        ]
        services = _get_services()
        if services:
            cmd += ["--service", *services]

        result = self.run_cmd(cmd, env=env)

        # Prowler exit codes:
        #   0  — scan ran, no failures (clean subscription)
        #   3  — scan ran, findings present (THIS IS NORMAL)
        #   1  — error (auth, network, internal). Stderr tail is the diagnostic.
        # We don't gate on returncode; we gate on output-file presence,
        # which is the authoritative "did Prowler produce structured data"
        # signal.
        ocsf_path = os.path.join(output_dir, f"{output_filename}.ocsf.json")
        if not os.path.exists(ocsf_path):
            stderr_tail = (result.stderr or "")[-1000:]
            raise RuntimeError(
                f"Prowler did not produce OCSF output at {ocsf_path} "
                f"(returncode={result.returncode}). Stderr tail: {stderr_tail!r}"
            )

        with open(ocsf_path, "r") as f:
            try:
                prowler_data: Any = json.load(f)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"Prowler emitted invalid JSON at {ocsf_path}: {e}"
                ) from e

        findings = normalize_prowler_findings(prowler_data, request)
        return findings
