import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Grade, Severity


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


def test_cts_eval_flagged_but_ungraded_and_capped(vuln):
    """CONTRACT CHANGED 2026-07-29 -- see the long rationale on
    ``test_param_injection_js.py::test_eval_and_new_function_are_flagged_but_ungraded_and_capped``."""
    hits = [f for f in vuln.findings
            if f.file.endswith("cjs.cts") and f.vuln_class == "code-eval"]
    assert hits
    assert all(f.grade is Grade.UNGRADED and f.grade_reason for f in hits)
    assert all(f.severity == Severity.P2 for f in hits)
    assert all(f.confidence is Confidence.LOW for f in hits)


def test_clean_mts_cts_quiet(clean):
    assert clean.files_scanned == 2
    assert clean.findings == [], (
        f"clean param_mts_cts fixtures should be quiet, got "
        f"{[(f.vuln_class, f.file, f.line) for f in clean.findings]}"
    )
