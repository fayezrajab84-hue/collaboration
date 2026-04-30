"""
GitHubPostureScanner — Phase 29 Slice C1.

Wraps Prowler 5.x's GitHub provider (`prowler github ...`) for posture
audits over a GitHub user / organization scope. Same architectural
pattern as CloudAzureScanner (Slice A) — env-var-based auth, OCSF JSON
output, normalizer to NormalizedFinding[].

  ScanRequest (target_type=GITHUB_ACCOUNT, scan_type=GITHUB_POSTURE)
              →  set GITHUB_PERSONAL_ACCESS_TOKEN env var
              →  invoke `prowler github --personal-access-token-from-env
                                         --output-modes json-ocsf`
              →  parse OCSF JSON
              →  normalize via Slice A's _generic_ Prowler normalizer
                 (same OCSF schema; only the evidence shape differs)

Why Prowler:
  - 24 community-maintained GitHub checks across organization /
    repository / githubactions services
  - Catches the highest-signal misconfigurations (MFA required, branch
    protection, secret scanning, dependabot, force-push, codeowners,
    stale-review dismissal, status checks, zizmor workflow analysis)
  - Same OCSF output as the Azure provider — re-uses existing
    normalizer infrastructure, no new format to parse
  - Future-proofs the integration — Prowler ships new GitHub checks
    on a regular cadence; we get them by bumping the image tag

Auth path:
  Both GitHub App installation tokens AND personal access tokens (PAT)
  reduce to a single bearer credential the API worker forwards to us
  via `request.github_credentials.token`. We expose it to Prowler via
  the GITHUB_PERSONAL_ACCESS_TOKEN env var (Prowler's standard auth
  variable for the github provider — works for both PAT and
  installation-token bearers).

Failure modes:
  - 401 from GitHub      → Prowler exits non-zero with auth error in
                           stderr; raised cleanly so the worker can
                           surface "token revoked / expired".
  - 403 (rate-limited or scope-too-narrow) → similar; stderr includes
                           the GitHub message.
  - Empty OCSF output    → no findings is valid (clean account); [].
  - Prowler not installed → exec fails; the worker reports rebuild needed.
"""
from __future__ import annotations

import json
import os
from typing import Any

from models import NormalizedFinding, ScanRequest
from ..base import BaseScanner
from ..cloud_azure.normalizer import normalize_prowler_findings


class GitHubPostureScanner(BaseScanner):
    """Activated when ScanRequest.scan_type == GITHUB_POSTURE and
    target_type == GITHUB_ACCOUNT. Requires github_credentials to be
    populated by the API worker (App installation token OR PAT, both
    surfaced as a single bearer string)."""

    scanner_name = "prowler-github"

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        creds = request.github_credentials
        if creds is None:
            raise ValueError("GITHUB_POSTURE scan requires github_credentials")
        if not creds.token:
            raise ValueError("github_credentials.token is empty")
        if not creds.account_login:
            raise ValueError("github_credentials.account_login is empty")

        # Workspace layout: same convention as cloud_azure.
        output_dir = os.path.join(workspace, "prowler-github-out")
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"scan-{request.scan_job_id}"

        # Token via env var so it doesn't show up in `ps`/proc.
        env = {
            "GITHUB_PERSONAL_ACCESS_TOKEN": creds.token,
        }

        # `--organization` scopes org-level checks; `--repository` scopes
        # repo-level. We pass `--organization` for ORGANIZATION accounts;
        # for USER accounts Prowler's defaults already enumerate the user's
        # repos. In both cases all 24 checks fire on the right scope.
        # Prowler 5.25 flag is `--personal-access-token` with no value —
        # passing it bare causes the CLI to read GITHUB_PERSONAL_ACCESS_TOKEN
        # from the environment (set above). Earlier drafts used a fictional
        # `--personal-access-token-from-env` flag which doesn't exist.
        cmd = [
            "prowler", "github",
            "--personal-access-token",
            "--output-modes", "json-ocsf",
            "--output-directory", output_dir,
            "--output-filename", output_filename,
        ]
        if creds.account_type == "ORGANIZATION":
            cmd += ["--organization", creds.account_login]

        result = self.run_cmd(cmd, env=env)

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

        # Reuse the cloud_azure normalizer — Prowler emits the same OCSF
        # compliance_finding schema for every provider. The only field
        # that's specifically Azure (cloud.account / cloud.org with
        # tenant identifiers) is gracefully empty for GitHub findings;
        # the normalizer's _cloud_block helper returns {} on miss so
        # no Azure-specific assumptions break.
        findings = normalize_prowler_findings(prowler_data, request)
        return findings
