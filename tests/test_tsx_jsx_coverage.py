"""Coverage + JSX-safety tests for .tsx/.jsx collection.

Two properties under test:
1. Real sinks inside .tsx/.jsx files still flag (param-injection,
   tool-scope-creep, secret-leak-response all fire on the vuln fixtures).
2. JSX syntax itself (angle-bracket trees, attribute `{...}` braces,
   conditional-render `{cond && <X/>}` braces, `{/* JSX comment */}`) does
   not trip any of those detectors on its own -- the clean fixtures carry
   the exact same JSX shapes and must stay quiet.
"""
import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import (
    ParamInjectionDetector,
    ToolScopeCreepDetector,
    SecretLeakResponseDetector,
)
from mcp_scanner.models import Severity

_DETECTORS = [
    ParamInjectionDetector(),
    ToolScopeCreepDetector(),
    SecretLeakResponseDetector(),
]


@pytest.fixture
def vuln_tsx(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_tsx_dashboard"), _DETECTORS)


@pytest.fixture
def clean_tsx(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_tsx_dashboard"), _DETECTORS)


@pytest.fixture
def vuln_jsx(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_jsx"), [ParamInjectionDetector()])


@pytest.fixture
def clean_jsx(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param_jsx"), [ParamInjectionDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


# --- .tsx: real sinks still flag -----------------------------------------

def test_tsx_file_is_collected(vuln_tsx):
    assert vuln_tsx.files_scanned >= 1
    assert all(f.file.endswith("Dashboard.tsx") for f in vuln_tsx.findings)


def test_tsx_eval_flagged(vuln_tsx):
    ev = [f for f in vuln_tsx.findings if f.vuln_class == "code-eval"]
    assert len(ev) >= 1
    assert all(f.severity == Severity.P0 for f in ev)


def test_tsx_ungated_mutating_tool_flagged(vuln_tsx):
    hits = [f for f in vuln_tsx.findings if f.vuln_class == "tool-scope-creep"]
    assert hits
    assert any("write_config" in f.title for f in hits)


def test_tsx_secret_named_field_flagged(vuln_tsx):
    hits = [f for f in vuln_tsx.findings if f.vuln_class == "secret-leak-via-tool-response"]
    assert hits
    assert any("apiKey" in f.detail or "Secret-named" in f.title for f in hits)


# --- .tsx: JSX itself never trips a finding --------------------------------

def test_tsx_clean_dashboard_quiet(clean_tsx):
    assert clean_tsx.files_scanned >= 1
    assert clean_tsx.findings == [], (
        "clean_tsx_dashboard (same JSX shapes, safe tool/eval code) must be "
        f"quiet, got: {[(f.vuln_class, f.title, f.line) for f in clean_tsx.findings]}"
    )


def test_tsx_vuln_findings_land_only_on_real_sink_lines(vuln_tsx):
    # No finding should land inside the JSX render block (StatusPanel body) --
    # every real finding above is on an eval/fs.writeFileSync/apiKey line,
    # all of which sit before the JSX in this fixture.
    jsx_only_lines = set(range(29, 38))  # StatusPanel export through closing brace
    bad = [f for f in vuln_tsx.findings if f.line in jsx_only_lines]
    assert bad == [], f"finding landed inside pure-JSX render code: {bad}"


# --- .jsx: collection parity + JSX-safety, lighter fixture -----------------

def test_jsx_file_is_collected_and_scanned(vuln_jsx):
    assert vuln_jsx.files_scanned >= 1
    assert all(f.file.endswith("Widget.jsx") for f in vuln_jsx.findings)


def test_jsx_shell_injection_flagged(vuln_jsx):
    assert "shell-injection" in _classes(vuln_jsx)


def test_jsx_clean_widget_quiet(clean_jsx):
    assert clean_jsx.files_scanned >= 1
    assert clean_jsx.findings == [], (
        f"clean_param_jsx should be quiet, got "
        f"{[(f.vuln_class, f.title, f.line) for f in clean_jsx.findings]}"
    )
