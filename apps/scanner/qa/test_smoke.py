"""
Smoke tests — every scanner is exercised against an appropriate vulnerable
fixture and asserts the basic contract:

  1. scan() does not raise
  2. returns a list of NormalizedFinding (the model contract)
  3. produces at least the expected number of findings
  4. each finding has a stable, non-empty fingerprint
  5. severities are valid enum values

These run in CI and on every scanner change. They take ~30s total because
the fixtures are tiny.
"""
import os
import pytest

from models import NormalizedFinding, ScanType, Severity


# Minimum finding counts per scanner against `vulnerable_repo` fixture.
# Conservative — bumping these as scanners get smarter is fine, but never
# lower them: a regression that drops findings should fail the test.
EXPECTED_MIN_FINDINGS = {
    ScanType.SAST:   2,   # eval, subprocess shell=True, sql formatting → ≥2 hits
    ScanType.SCA:    1,   # lodash 4.17.4 alone has multiple CVEs
    ScanType.SECRET: 1,   # AKIA fake key
    ScanType.IAC:    3,   # public S3, public ACL, SSH/RDP from world
}


def _assert_finding_contract(f: NormalizedFinding) -> None:
    """Every finding must satisfy these invariants — the API depends on them."""
    assert isinstance(f, NormalizedFinding), f"got {type(f).__name__}"
    assert f.fingerprint, "finding must have a non-empty fingerprint"
    assert len(f.fingerprint) >= 16, f"fingerprint too short: {f.fingerprint}"
    assert f.title, "finding must have a title"
    assert f.severity in Severity, f"unknown severity: {f.severity}"
    assert f.scan_type in ScanType, f"unknown scan_type: {f.scan_type}"


def test_repo_scanner_smoke(repo_scanner, vulnerable_repo_url, make_request):
    """SAST/SCA/SECRET/IAC: clone fixture, scan, assert contract."""
    scan_type, scanner, workspace = repo_scanner
    request = make_request(scan_type, repo_url=vulnerable_repo_url)

    findings = scanner.scan(request, workspace)

    assert isinstance(findings, list)
    expected_min = EXPECTED_MIN_FINDINGS[scan_type]
    assert len(findings) >= expected_min, (
        f"{scan_type.value} produced {len(findings)} findings, "
        f"expected ≥{expected_min}. Did the scanner break or did the fixture change?"
    )

    for f in findings:
        _assert_finding_contract(f)


def test_fingerprints_are_stable(repo_scanner, vulnerable_repo_url, make_request):
    """Re-scanning the same fixture must produce the same fingerprints — this is
    the dedup contract the API relies on. A regression here causes the entire
    finding-history mechanism to break."""
    scan_type, scanner, workspace1 = repo_scanner

    # First run on the parametrized scanner's workspace
    fp_run1 = sorted(f.fingerprint for f in scanner.scan(
        make_request(scan_type, repo_url=vulnerable_repo_url), workspace1))

    # Second run in a fresh workspace using the same scanner class — exactly
    # what happens on a re-scan in production.
    workspace2 = scanner.make_workspace()
    try:
        fp_run2 = sorted(f.fingerprint for f in scanner.scan(
            make_request(scan_type, repo_url=vulnerable_repo_url), workspace2))
    finally:
        scanner.cleanup(workspace2)

    assert fp_run1 == fp_run2, (
        f"{scan_type.value} fingerprints not stable across runs:\n"
        f"  only in run1: {set(fp_run1) - set(fp_run2)}\n"
        f"  only in run2: {set(fp_run2) - set(fp_run1)}"
    )


# ── Container scanner — exercised against a small public image ────────────────
# Skip when we can't pull (offline CI etc). Uses alpine:3.10 which has known
# CVEs but is tiny (~5 MB) compared to node:14.

@pytest.mark.skipif(
    os.environ.get("QA_SKIP_NETWORK") == "1",
    reason="network-dependent test disabled by QA_SKIP_NETWORK=1",
)
def test_container_scanner_smoke(container_scanner, make_request):
    scanner, workspace = container_scanner
    request = make_request(
        ScanType.CONTAINER,
        target_type="CONTAINER",
        image_ref="alpine:3.10",
    )
    findings = scanner.scan(request, workspace)
    assert isinstance(findings, list)
    # alpine:3.10 has well-known CVEs — at minimum musl/openssl issues
    assert len(findings) >= 1, "alpine:3.10 should yield ≥1 CVE; scanner may be broken"
    for f in findings:
        _assert_finding_contract(f)
        # SCA/CONTAINER findings should have a CVE id when applicable
        if f.cve_id:
            assert f.cve_id.startswith("CVE-"), f"malformed CVE id: {f.cve_id}"


# ── DAST / PENTEST_FULL — gated behind explicit env var ────────────────────────
# These require a running DAST target (DVWA) and take minutes. Not part of the
# default smoke suite — run with `pytest -m slow_network` when validating those
# specific scanners.

@pytest.mark.slow_network
@pytest.mark.skipif(
    not os.environ.get("QA_DAST_TARGET"),
    reason="set QA_DAST_TARGET=dvwa (or similar reachable hostname) to run",
)
def test_dast_smoke(make_request):
    from scanners import DASTScanner
    scanner   = DASTScanner()
    workspace = scanner.make_workspace()
    try:
        target  = os.environ["QA_DAST_TARGET"]
        request = make_request(ScanType.DAST, target_type="DOMAIN", domain=target)
        findings = scanner.scan(request, workspace)
        assert isinstance(findings, list)
        # DAST against DVWA always produces ≥1 finding (default ZAP rules find
        # missing security headers at minimum).
        assert len(findings) >= 1, f"DAST against {target} produced 0 findings"
        for f in findings:
            _assert_finding_contract(f)
    finally:
        scanner.cleanup(workspace)
