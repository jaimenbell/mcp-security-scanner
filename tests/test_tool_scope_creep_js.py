from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Severity, Confidence

import pytest


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_tool_scope_js"), [ToolScopeCreepDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_tool_scope_js"), [ToolScopeCreepDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_ungated_mutating_js_tools_flagged(vuln):
    assert "tool-scope-creep" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "tool-scope-creep"]
    # both delete_file (fs.unlinkSync) and run_shell (exec) should fire
    assert len(hits) >= 2
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_ungated_js_tool_title_names_the_tool(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles
    assert "run_shell" in titles


def test_gated_js_tool_and_readonly_tool_quiet(clean):
    assert clean.findings == [], (
        "gated mutating tool + read-only tool must not be flagged, got: "
        f"{[(f.vuln_class, f.file, f.line) for f in clean.findings]}"
    )
