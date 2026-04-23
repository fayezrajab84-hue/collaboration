"""
QA harness fixtures.

Creates a local bare git repo from `qa/fixtures/vulnerable_repo/` so SAST/SCA/
SECRET/IAC scanners can clone it via the standard `clone_repo()` path —
exercising the *real* code path the API uses, not a mocked one.

Network-dependent scanners (DAST, PENTEST_FULL, CONTAINER) use a separate
fixture: a hostname/image they assume is reachable from inside the scanner
network. Those tests skip cleanly if the target is unavailable.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

# Make the parent `scanner` package importable when pytest is invoked from
# inside the container at /app/apps/scanner/qa
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import ScanRequest, ScanType                # noqa: E402
from scanners import (                                   # noqa: E402
    SASTScanner, SCAScanner, SecretsScanner, IACScanner,
    ContainerScanner, DASTScanner, PentestScanner, PentestFullScanner,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "vulnerable_repo"


@pytest.fixture(scope="session")
def vulnerable_repo_url(tmp_path_factory) -> str:
    """Materialize the fixture directory as a local bare git repo and return
    a file:// URL that the scanners' clone_repo() can consume.

    Session-scoped so all scanner tests share the same repo (faster) and the
    clone-cache in base.py warms naturally.
    """
    workdir = tmp_path_factory.mktemp("qa-fixture")
    src     = workdir / "src"
    bare    = workdir / "vulnerable.git"

    # Copy fixture files into a temp working tree
    shutil.copytree(FIXTURES_DIR, src)

    # Init + commit
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME":     "qa", "GIT_AUTHOR_EMAIL":     "qa@local",
        "GIT_COMMITTER_NAME":  "qa", "GIT_COMMITTER_EMAIL":  "qa@local",
    }
    subprocess.run(["git", "init", "--initial-branch=main", str(src)],   check=True, env=env, capture_output=True)
    subprocess.run(["git", "-C", str(src), "add", "."],                  check=True, env=env, capture_output=True)
    subprocess.run(["git", "-C", str(src), "commit", "-m", "qa fixture"],check=True, env=env, capture_output=True)

    # Bare clone — file:// URLs work natively with `git clone`
    subprocess.run(["git", "clone", "--bare", str(src), str(bare)], check=True, env=env, capture_output=True)
    return f"file://{bare}"


def _make_request(scan_type: ScanType, repo_url: str | None = None, **extra) -> ScanRequest:
    """Build a minimal ScanRequest. Most scanners only need orgId/targetId/repo_url."""
    return ScanRequest(
        scan_job_id=f"qa-{uuid.uuid4().hex[:12]}",
        org_id="qa-org",
        target_type="REPOSITORY" if repo_url else extra.pop("target_type", "DOMAIN"),
        target_id="qa-target",
        scan_type=scan_type,
        repo_url=repo_url,
        branch="main",
        **extra,
    )


@pytest.fixture
def make_request():
    return _make_request


# Per-scanner factories — used by tests so we don't repeat the boilerplate
SCANNER_FIXTURES = {
    ScanType.SAST:         SASTScanner,
    ScanType.SCA:          SCAScanner,
    ScanType.SECRET:       SecretsScanner,
    ScanType.IAC:          IACScanner,
    ScanType.CONTAINER:    ContainerScanner,
    ScanType.DAST:         DASTScanner,
    ScanType.PENTEST:      PentestScanner,
    ScanType.PENTEST_FULL: PentestFullScanner,
}


@pytest.fixture(params=[ScanType.SAST, ScanType.SCA, ScanType.SECRET, ScanType.IAC],
                ids=["sast", "sca", "secret", "iac"])
def repo_scanner(request):
    """Parametrize over the four scanners that operate on a cloned repo.
    Yields (scan_type, scanner_instance, workspace_dir). Cleans workspace after."""
    scan_type = request.param
    scanner   = SCANNER_FIXTURES[scan_type]()
    workspace = scanner.make_workspace()
    try:
        yield scan_type, scanner, workspace
    finally:
        scanner.cleanup(workspace)


@pytest.fixture
def container_scanner():
    s = ContainerScanner()
    ws = s.make_workspace()
    yield s, ws
    s.cleanup(ws)
