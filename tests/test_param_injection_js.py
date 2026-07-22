import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_js"), [ParamInjectionDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param_js"), [ParamInjectionDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_exec_and_shell_spawn_flagged(vuln):
    assert "shell-injection" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "shell-injection"]
    assert len(hits) >= 2


def test_eval_and_new_function_are_critical(vuln):
    ev = [f for f in vuln.findings if f.vuln_class == "code-eval"]
    assert len(ev) >= 2
    assert all(f.severity == Severity.P0 for f in ev)


def test_ssrf_and_traversal_flagged(vuln):
    assert "ssrf" in _classes(vuln)
    assert "path-traversal" in _classes(vuln)


def test_findings_land_on_js_file(vuln):
    assert all(f.file.endswith("server.js") for f in vuln.findings)


def test_clean_param_js_quiet(clean):
    bad = [f for f in clean.findings
           if f.vuln_class in ("shell-injection", "code-eval",
                               "unsafe-deserialization", "ssrf", "path-traversal")]
    assert bad == [], f"clean param_js fixture should be quiet, got {bad}"
