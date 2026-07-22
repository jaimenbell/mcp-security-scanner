import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_cjs"), [ParamInjectionDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param_cjs"), [ParamInjectionDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_cjs_file_is_collected_and_scanned(vuln):
    # If .cjs weren't in _SCAN_SUFFIXES / JS_SUFFIXES, files_scanned would be 0
    # and none of the checks below would ever fire.
    assert vuln.files_scanned >= 1
    assert all(f.file.endswith("server.cjs") for f in vuln.findings)


def test_exec_and_shell_spawn_flagged(vuln):
    assert "shell-injection" in _classes(vuln)


def test_eval_flagged_as_critical(vuln):
    ev = [f for f in vuln.findings if f.vuln_class == "code-eval"]
    assert len(ev) >= 1
    assert all(f.severity == Severity.P0 for f in ev)


def test_ssrf_and_traversal_flagged(vuln):
    assert "ssrf" in _classes(vuln)
    assert "path-traversal" in _classes(vuln)


def test_clean_param_cjs_quiet(clean):
    assert clean.files_scanned >= 1
    bad = [f for f in clean.findings
           if f.vuln_class in ("shell-injection", "code-eval",
                               "unsafe-deserialization", "ssrf", "path-traversal")]
    assert bad == [], f"clean param_cjs fixture should be quiet, got {bad}"
