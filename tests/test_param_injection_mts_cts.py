import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_mts_cts"), [ParamInjectionDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param_mts_cts"), [ParamInjectionDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_mts_and_cts_files_are_collected(vuln):
    # Two fixture files, one per new suffix -- both must be scanned.
    assert vuln.files_scanned == 2


def test_mts_shell_injection_flagged(vuln):
    hits = [f for f in vuln.findings if f.file.endswith("esm.mts")]
    assert any(f.vuln_class == "shell-injection" for f in hits)


def test_cts_eval_flagged(vuln):
    hits = [f for f in vuln.findings if f.file.endswith("cjs.cts")]
    assert any(f.vuln_class == "code-eval" and f.severity == Severity.P0 for f in hits)


def test_clean_mts_cts_quiet(clean):
    assert clean.files_scanned == 2
    assert clean.findings == [], (
        f"clean param_mts_cts fixtures should be quiet, got "
        f"{[(f.vuln_class, f.file, f.line) for f in clean.findings]}"
    )
