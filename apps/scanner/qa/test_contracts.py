"""
Contract tests — run against the Python objects, not the network. Catch
basic refactor regressions before they ever reach a scan run.
"""
import inspect

import pytest

from main import SCANNER_MAP
from models import NormalizedFinding, ScanType
from scanners.base import BaseScanner


@pytest.mark.parametrize("scan_type", list(ScanType))
def test_every_scan_type_has_a_scanner(scan_type):
    """Every ScanType enum value MUST be wired to a scanner class. Adding a
    new ScanType without a scanner is a release-blocker."""
    assert scan_type in SCANNER_MAP, (
        f"ScanType.{scan_type.name} is in the enum but missing from SCANNER_MAP "
        f"in main.py — every scan type must be implementable."
    )


@pytest.mark.parametrize("scan_type,scanner_cls", list(SCANNER_MAP.items()),
                         ids=lambda v: v.name if hasattr(v, "name") else v.__name__)
def test_scanner_inherits_base(scan_type, scanner_cls):
    """All scanners must extend BaseScanner — gives them clone_repo,
    compute_fingerprint, make_workspace, and severity mapping helpers."""
    assert issubclass(scanner_cls, BaseScanner), (
        f"{scanner_cls.__name__} for {scan_type.name} doesn't inherit BaseScanner — "
        "it would be missing fingerprint helpers."
    )


@pytest.mark.parametrize("scan_type,scanner_cls", list(SCANNER_MAP.items()),
                         ids=lambda v: v.name if hasattr(v, "name") else v.__name__)
def test_scanner_implements_scan(scan_type, scanner_cls):
    """The scan() method is the public contract every scanner must provide."""
    assert hasattr(scanner_cls, "scan"), f"{scanner_cls.__name__} missing scan()"
    sig = inspect.signature(scanner_cls.scan)
    params = list(sig.parameters.keys())
    # self, request, workspace
    assert len(params) >= 3, (
        f"{scanner_cls.__name__}.scan() expected (self, request, workspace), "
        f"got {params}"
    )


def test_normalized_finding_required_fields():
    """The NormalizedFinding model is the contract between scanner ↔ API.
    Removing/renaming a required field is a breaking change that must be
    coordinated with the API's findingService.upsertFindings."""
    required = {"fingerprint", "rule_id", "title", "description", "severity", "scan_type"}
    actual_fields = set(NormalizedFinding.model_fields.keys())
    missing = required - actual_fields
    assert not missing, (
        f"NormalizedFinding lost required fields: {missing}. "
        "Coordinate with apps/api/src/services/findingService.ts before removing."
    )
