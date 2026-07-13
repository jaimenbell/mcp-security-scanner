import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import AuthPostureDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_auth"), [AuthPostureDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_auth"), [AuthPostureDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_bind_all_plus_debug_is_high(vuln):
    ne = [f for f in vuln.findings if f.vuln_class == "network-exposure"]
    assert ne, "0.0.0.0 bind should be flagged"
    assert any(f.severity == Severity.P1 for f in ne), "0.0.0.0+debug -> P1"


def test_unauth_mutating_route_flagged(vuln):
    assert "missing-auth" in _classes(vuln)


def test_clean_auth_no_high(clean):
    highs = [f for f in clean.findings if f.severity in (Severity.P0, Severity.P1)]
    assert highs == [], f"clean auth fixture must have no P0/P1, got {highs}"
    # loopback bind must not be flagged as network-exposure
    assert "network-exposure" not in _classes(clean)
    # route has Depends -> not flagged missing-auth
    assert "missing-auth" not in _classes(clean)
