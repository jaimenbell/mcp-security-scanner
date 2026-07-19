from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Severity, Confidence

import pytest


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_tool_scope"), [ToolScopeCreepDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_tool_scope"), [ToolScopeCreepDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_ungated_mutating_tool_flagged(vuln):
    assert "tool-scope-creep" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "tool-scope-creep"]
    # both delete_file (os.remove) and run_shell (subprocess) should fire
    assert len(hits) >= 2
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_ungated_tool_title_names_the_tool(vuln):
    hits = [f for f in vuln.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles
    assert "run_shell" in titles


def test_gated_tool_quiet_via_one_hop_delegation(clean):
    """Clean fixture models the real fleet shape: a thin @mcp.tool() wrapper
    in server.py delegates to a helper in write.py that is decorated with a
    gate one hop away -- this must not false-positive."""
    assert clean.findings == [], (
        "properly-gated tools (one hop through a decorated helper) must not "
        f"be flagged, got: {[(f.vuln_class, f.file, f.line) for f in clean.findings]}"
    )


def test_read_only_tool_not_classified_mutating():
    """A tool with a non-mutating verb name and no dangerous body sink is
    never flagged, regardless of gating."""
    det = ToolScopeCreepDetector()
    from mcp_scanner.scanner import build_context
    import tempfile, os as _os
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.py"
        p.write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n\n"
            "@mcp.tool(name='get_status')\n"
            "async def get_status_tool() -> dict:\n"
            "    return {'ok': True}\n",
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        findings = det.run(ctx)
        assert findings == []
