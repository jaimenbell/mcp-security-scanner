import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param"), [ParamInjectionDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param"), [ParamInjectionDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_shell_true_flagged(vuln):
    assert "shell-injection" in _classes(vuln)


def test_eval_is_critical(vuln):
    ev = [f for f in vuln.findings if f.vuln_class == "code-eval"]
    assert ev and ev[0].severity == Severity.P0


def test_pickle_and_yaml_flagged(vuln):
    assert "unsafe-deserialization" in _classes(vuln)
    titles = " ".join(f.title for f in vuln.findings)
    assert "pickle" in titles and "yaml.load" in titles


def test_ssrf_and_traversal_flagged(vuln):
    assert "ssrf" in _classes(vuln)
    assert "path-traversal" in _classes(vuln)


def test_clean_param_quiet(clean):
    # No high-signal sinks; the only tolerable output would be none.
    bad = [f for f in clean.findings
           if f.vuln_class in ("shell-injection", "code-eval",
                               "unsafe-deserialization", "ssrf", "path-traversal")]
    assert bad == [], f"clean param fixture should be quiet, got {bad}"
