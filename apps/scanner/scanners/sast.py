from __future__ import annotations
import json
import logging

from models import Confidence, NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner

logger = logging.getLogger(__name__)

# ── Rule-ID → ScanType classification ────────────────────────────────────────
# Semgrep --config auto downloads rules for SAST, IaC, and secrets in one run.
# We classify each finding by its check_id prefix so it is stored under the
# correct scan type (with the correct fingerprint).

_IAC_PREFIXES = (
    "terraform.",
    "cloudformation.",
    "kubernetes.",
    "dockerfile.",
    "docker.",
    "helm.",
    "ansible.",
    "arm.",
    "bicep.",
    "github-actions.",
)

_SECRET_PREFIXES = (
    "generic.secrets.",
    "secrets.",
    "trufflehog.",
    "tokens.",
    "credentials.",
)


def _classify_scan_type(check_id: str, metadata: dict) -> ScanType:
    """Map a Semgrep rule ID to the appropriate ScanType."""
    cid = check_id.lower()
    if any(cid.startswith(p) for p in _IAC_PREFIXES):
        return ScanType.IAC
    if any(cid.startswith(p) for p in _SECRET_PREFIXES):
        return ScanType.SECRET
    # Some AWS/provider credential rules live under terraform.* but are secrets
    technologies = metadata.get("technology", []) if isinstance(metadata.get("technology"), list) else []
    if "secrets" in [t.lower() for t in technologies] and "terraform" not in [t.lower() for t in technologies]:
        return ScanType.SECRET
    return ScanType.SAST


def _prefix_with_line_numbers(snippet: str, start_line: int | None, end_line: int | None) -> str:
    """Prefix every snippet line with ``"{N}: "`` using the real 1-based line numbers.

    Semgrep's ``extra.lines`` is meant to be ``start.line``→``end.line``, but in
    practice it often pads to a complete statement/element (e.g. a Java/HTML
    match on an attribute returns the whole enclosing tag). When that happens
    the snippet has MORE lines than ``end.line - start.line + 1``, so naively
    numbering from ``start_line`` shifts the gutter (and the
    vulnerable-line highlight) by the pad amount.

    Strategy: if the snippet is larger than expected, count backwards from
    ``end_line`` so the last line is labelled ``end_line`` and the highlight
    still lands on the real matched line. Falls back to ``start_line`` when
    we can't determine better.

    The ``"N: "`` format mirrors ``_read_snippet`` so the frontend's
    SyntaxHighlight parser recovers the numbers in both cases.
    """
    if not snippet:
        return snippet
    lines = snippet.split("\n")
    # Drop a trailing blank line — semgrep occasionally adds one
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if not lines:
        return snippet

    # Decide the first-line number
    if start_line is None:
        return snippet  # nothing sensible to anchor to
    expected = (end_line - start_line + 1) if (end_line and end_line >= start_line) else len(lines)
    if len(lines) > expected and end_line:
        first = max(1, end_line - len(lines) + 1)
    else:
        first = start_line

    return "\n".join(f"{first + i}: {line}" for i, line in enumerate(lines))


def _read_snippet(file_path: str, line_num: int | None, context: int = 2) -> str | None:
    """Read ±context lines around line_num from a local file.

    Used as a fallback when Semgrep returns the "requires login" Pro paywall
    placeholder instead of the matched lines (common for `generic.secrets.*`
    rules in the community engine).

    Emits each line with a ``"{N}: {content}"`` prefix so the frontend
    SyntaxHighlight parser recovers the real 1-based line numbers — otherwise
    the gutter would show shifted numbers and the vulnerable-line highlight
    would land on a context row instead of the matched line.
    """
    if not line_num:
        return None
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        start = max(0, line_num - context - 1)
        end   = min(len(lines), line_num + context)
        out = "\n".join(
            f"{start + i + 1}: {lines[start + i].rstrip()}"
            for i in range(end - start)
        )
        return out[:1200]
    except Exception:
        return None


class SASTScanner(BaseScanner):
    """SAST scanner using Semgrep."""

    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        if not request.repo_url or not request.branch:
            raise ValueError("repo_url and branch required for SAST scan")

        repo_dir = f"{workspace}/repo"
        self.clone_repo(request.repo_url, request.branch, request.git_token, repo_dir)

        # ── Incremental mode ──────────────────────────────────────────────
        # When the API supplies a changed-files list (e.g. from a PR webhook),
        # restrict Semgrep to those paths via --include. Semgrep accepts
        # --include multiple times; patterns are glob-style relative to cwd.
        # If no files are provided, scan the full tree as before.
        cmd = ["semgrep", "--config", "auto", "--json", "--no-git-ignore"]
        if request.changed_files:
            for path in request.changed_files:
                cmd.extend(["--include", path])
            logger.info("[sast] incremental mode — %d changed file(s)", len(request.changed_files))
        cmd.append(".")

        result = self.run_cmd(cmd, cwd=repo_dir)

        # ── Detect semgrep crashes early ──────────────────────────────────
        # semgrep may exit non-zero even when it found things (file-parse errors,
        # rule download warnings). Only treat it as a hard failure when stdout is
        # absent or clearly not JSON — that means semgrep itself crashed (e.g.
        # missing pkg_resources / broken install).
        stdout = (result.stdout or "").strip()
        if not stdout:
            stderr_snippet = (result.stderr or "")[:600]
            raise RuntimeError(
                f"semgrep produced no output (exit {result.returncode}). "
                f"stderr: {stderr_snippet}"
            )

        findings: list[NormalizedFinding] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"semgrep output is not valid JSON (exit {result.returncode}): {exc}. "
                f"First 200 chars: {stdout[:200]}"
            ) from exc

        # Log parse errors from semgrep (non-fatal — some files may be unparseable)
        errors = data.get("errors", [])
        if errors:
            logger.warning("[sast] semgrep reported %d file errors (non-fatal)", len(errors))

        for item in data.get("results", []):
            check_id  = item.get("check_id", "unknown")
            path      = item.get("path", "")
            line_start = item.get("start", {}).get("line")
            line_end   = item.get("end",   {}).get("line")
            message    = item.get("extra", {}).get("message", "")
            sev_str    = item.get("extra", {}).get("severity", "INFO")
            metadata   = item.get("extra", {}).get("metadata", {})
            raw_snippet = item.get("extra", {}).get("lines", "") or ""
            # "requires login" is a Semgrep Pro paywall placeholder — not real code.
            # When Semgrep withholds the lines (common for taint-mode and
            # generic.secrets.* rules in the community engine), read them off
            # the cloned repo instead so the developer still sees the actual
            # code — BUT mark the location as approximate, because for
            # taint-mode rules the reported `start.line` is the taint *source*
            # (e.g. the decode call) rather than the dangerous *sink*. Without
            # the Pro dataflow_trace we cannot point to the exact sink, so
            # the frontend should avoid highlighting a single misleading line.
            is_paywalled = raw_snippet.strip().lower() == "requires login"
            snippet = "" if is_paywalled else raw_snippet
            location_approximate = False
            if not snippet and path:
                local_path = f"{repo_dir}/{path}" if not path.startswith(repo_dir) else path
                disk_snippet = _read_snippet(local_path, line_start)
                if disk_snippet:
                    snippet = disk_snippet  # already "N: " prefixed
                    # Only the paywalled case produces an approximate location;
                    # other fallbacks (empty extra.lines on a non-taint rule)
                    # still have trustworthy start/end coordinates.
                    if is_paywalled:
                        location_approximate = True
            elif snippet:
                # Annotate raw extra.lines with true line numbers so the gutter
                # matches GitHub (Semgrep often pads to full statements/tags).
                snippet = _prefix_with_line_numbers(snippet, line_start, line_end)

            # Classify the finding into the correct scan type based on rule ID
            scan_type   = _classify_scan_type(check_id, metadata)
            severity    = self.map_semgrep_severity(sev_str)
            fingerprint = self.compute_fingerprint(
                request.org_id, request.target_id, scan_type,
                check_id, path, line_start,
            )

            # Semgrep metadata may carry a confidence field ("HIGH"/"MEDIUM"/"LOW")
            semgrep_confidence = str(metadata.get("confidence", "")).upper()
            confidence = Confidence.CONFIRMED if semgrep_confidence == "HIGH" else Confidence.LIKELY

            # Build a human title from the rule ID tail
            title = check_id.split(".")[-1].replace("-", " ").title()

            findings.append(NormalizedFinding(
                fingerprint=fingerprint,
                rule_id=check_id,
                title=title,
                description=message,
                severity=severity,
                scan_type=scan_type,
                scanner="semgrep",
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet[:500] if snippet else None,
                cwe_id=(
                    metadata.get("cwe", [None])[0]
                    if isinstance(metadata.get("cwe"), list)
                    else metadata.get("cwe")
                ),
                remediation=metadata.get("fix"),
                references=metadata.get("references", []),
                raw_output=item,
                confidence=confidence,
                evidence={
                    "rule_id":              check_id,
                    "file":                 path,
                    "line":                 line_start,
                    "snippet":              snippet[:300] if snippet else "",
                    "semgrep_confidence":   semgrep_confidence or "not set",
                    "classified_as":        scan_type.value,
                    "location_approximate": location_approximate,
                },
            ))

        logger.info("[sast] semgrep returned %d findings", len(findings))
        return findings
