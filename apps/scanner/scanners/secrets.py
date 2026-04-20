from __future__ import annotations
import json
import re

from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner


def _read_snippet(file_path: str, line_num: int, context: int = 2) -> str | None:
    """Read ±context lines around line_num from a local file.

    Returns a numbered snippet string (same format as SAST), or None on error.
    The matched line itself is included; the secret value remains visible so the
    developer can confirm the finding — TruffleHog already stripped the raw
    bytes from its JSON output.
    """
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        start = max(0, line_num - context - 1)   # line_num is 1-based
        end   = min(len(lines), line_num + context)
        slice_ = lines[start:end]
        return "".join(
            f"{start + i + 1}: {ln}" for i, ln in enumerate(slice_)
        ).rstrip()[:1000]
    except Exception:
        return None

# ── Path helpers ──────────────────────────────────────────────────────────────

_WORKSPACE_RE = re.compile(r"^/tmp/scan_workspace/[^/]+/repo/")

def _clean_path(raw: str) -> str:
    """Strip the scanner workspace prefix, returning a repo-relative path."""
    return _WORKSPACE_RE.sub("", raw).lstrip("/")


# Files that commonly trigger false positives but don't represent real secrets
# in committed source code. Git internals are clone-URL artefacts; lock files
# contain package hashes, not credentials.
_SKIP_PATHS = (
    ".git/",                  # git internals — clone URL with embedded token
    "package-lock.json",      # npm lock — hash values
    "yarn.lock",              # yarn lock
    "pnpm-lock.yaml",         # pnpm lock
    "composer.lock",          # PHP lock
    "Pipfile.lock",           # Python lock
    "poetry.lock",            # Poetry lock
    "Gemfile.lock",           # Ruby lock
    "go.sum",                 # Go checksums
    "Cargo.lock",             # Rust lock
)

def _should_skip(repo_relative_path: str) -> bool:
    lower = repo_relative_path.lower()
    return any(lower.startswith(p.lower()) or lower.endswith(p.lower()) for p in _SKIP_PATHS)


class SecretsScanner(BaseScanner):
    """Secret scanner using TruffleHog."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.repo_url or not request.branch:
            raise ValueError("repo_url and branch required for secrets scan")

        repo_dir = f"{workspace}/repo"
        self.clone_repo(request.repo_url, request.branch, request.git_token, repo_dir)

        result = self.run_cmd([
            "trufflehog", "filesystem",
            "--json",
            "--no-update",
            repo_dir,
        ])

        findings: list[NormalizedFinding] = []

        # TruffleHog outputs newline-delimited JSON
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector    = item.get("DetectorName", "unknown")
            source_data = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            raw_path    = source_data.get("file", "")
            line_num    = source_data.get("line")
            verified    = item.get("Verified", False)

            # ── Clean the path ────────────────────────────────────────────
            clean_path = _clean_path(raw_path)

            # ── Skip git internals and dependency lock files ──────────────
            if _should_skip(clean_path):
                continue

            # Higher severity for verified (active) secrets
            severity = Severity.CRITICAL if verified else Severity.HIGH

            # Fingerprint uses the clean repo-relative path so it stays stable
            # across re-scans (different workspace UUIDs, same repo path)
            fingerprint = self.compute_fingerprint(
                request.org_id, request.target_id, ScanType.SECRET,
                detector, clean_path, line_num
            )

            confidence = Confidence.CONFIRMED if verified else Confidence.LIKELY

            # Read snippet from the cloned repo on disk (±2 lines of context)
            local_path = f"{repo_dir}/{clean_path}"
            snippet: str | None = None
            if line_num:
                snippet = _read_snippet(local_path, int(line_num))

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=detector,
                title=f"Secret detected: {detector}",
                description=(
                    f"{'⚠️ VERIFIED ACTIVE SECRET' if verified else 'Potential secret'}: "
                    f"{detector} credential found in {clean_path} at line {line_num or '?'}. "
                    f"Immediately rotate this credential and remove it from the repository."
                ),
                severity=severity,
                scan_type=ScanType.SECRET,
                scanner="trufflehog",
                file_path=clean_path,              # repo-relative, no workspace prefix
                line_start=int(line_num) if line_num else None,
                code_snippet=snippet,
                remediation=(
                    "Remove the hardcoded credential from source code. "
                    "Load secrets from environment variables or a secrets manager "
                    "(e.g. AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets). "
                    "Rotate the credential immediately — treat it as compromised."
                ),
                raw_output={k: v for k, v in item.items() if k != "Raw"},  # never store raw secret
                confidence=confidence,
                evidence={
                    "detector": detector,
                    "file":     clean_path,
                    "line":     line_num,
                    "verified": verified,
                    "detail": (
                        "TruffleHog verified this secret is active by calling the target API"
                        if verified else
                        "TruffleHog pattern-matched a secret but could not verify it is active"
                    ),
                },
            ))

        return findings
