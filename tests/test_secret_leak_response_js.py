import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretLeakResponseDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_secret_leak_js"), [SecretLeakResponseDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_secret_leak_js"), [SecretLeakResponseDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_process_env_returned_wholesale_is_critical(vuln):
    hits = [f for f in vuln.findings if "process.env" in f.title]
    assert hits and hits[0].severity == Severity.P0


def test_whole_config_object_returned_flagged(vuln):
    titles = " ".join(f.title for f in vuln.findings)
    assert "config" in titles.lower() or "Whole config" in titles


def test_secret_named_field_and_hardcoded_value_flagged(vuln):
    titles = " ".join(f.title for f in vuln.findings)
    assert "Secret-named" in titles
    assert "Hardcoded" in titles


def test_clean_secret_leak_js_quiet(clean):
    assert clean.findings == [], (
        f"clean secret_leak_js fixture should be quiet, got "
        f"{[(f.title, f.file, f.line) for f in clean.findings]}"
    )
