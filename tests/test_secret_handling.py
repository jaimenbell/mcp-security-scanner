from pathlib import Path

import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.base import RepoContext
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_secret"), [SecretHandlingDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_secret"), [SecretHandlingDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_hardcoded_secret_flagged(vuln):
    assert "hardcoded-secret" in _classes(vuln)
    hs = [f for f in vuln.findings if f.vuln_class == "hardcoded-secret"]
    assert any(f.severity == Severity.P1 for f in hs)


def test_secret_in_log_flagged(vuln):
    assert "secret-in-log" in _classes(vuln)


def test_clean_secret_quiet(clean):
    bad = [f for f in clean.findings
           if f.vuln_class in ("hardcoded-secret", "tracked-secret-file")]
    assert bad == [], f"env-sourced secrets must not be flagged, got {bad}"


def test_tracked_dotenv_flagged():
    # Unit-level: a tracked .env in the git manifest is a P1 regardless of content.
    det = SecretHandlingDetector()
    ctx = RepoContext(root=Path("."), files=[], tracked={".env", "src/app.py"}, is_git=True)
    findings = det.run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf and tf[0].severity == Severity.P1


def test_env_example_not_flagged():
    det = SecretHandlingDetector()
    ctx = RepoContext(root=Path("."), files=[], tracked={".env.example"}, is_git=True)
    findings = det.run(ctx)
    assert [f for f in findings if f.vuln_class == "tracked-secret-file"] == []
