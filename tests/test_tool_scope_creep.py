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


@pytest.fixture
def clean_same_file(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_tool_scope_same_file_gate"), [ToolScopeCreepDetector()])


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


def test_gated_tool_quiet_via_one_hop_delegation_same_file(clean_same_file):
    """A thin @mcp.tool() wrapper delegates one hop to a gated helper defined
    in the SAME file -- this must not false-positive. This is the one-hop
    feature's core covered case after the 2026-07-23 same-file-only fix
    (see test_cross_file_gate_now_over_flags_by_design below for the
    cross-file case this fix deliberately no longer follows)."""
    assert clean_same_file.findings == [], (
        "a same-file one-hop gated helper must not be flagged, got: "
        f"{[(f.vuln_class, f.file, f.line) for f in clean_same_file.findings]}"
    )


def test_cross_file_gate_now_over_flags_by_design(clean):
    """2026-07-23 (closing the README's named follow-up): `clean_tool_scope`
    models a thin @mcp.tool() wrapper in server.py that delegates to a gated
    helper in a SEPARATE file, write.py -- previously quiet because the
    decorator path's func_index/gated_names were built REPO-WIDE by bare
    short function name. An N-vote refuter proved that same repo-wide index
    let an unrelated, never-imported, same-named gated helper elsewhere in
    the repo silence a genuinely UNGATED tool (a false negative on this
    detector's primary target class). The fix scopes the index same-file-
    only (matching the low-level SDK path's pre-existing convention), which
    honestly costs this genuinely-gated-but-cross-file case too: the hop to
    write.py is no longer followed, so these two tools are now (correctly,
    per this detector's own accept-over-flag-rather-than-miss philosophy)
    flagged low-confidence/P2 rather than silently cleared. This pins the
    new, honest behavior -- it is not a regression."""
    hits = [f for f in clean.findings if f.vuln_class == "tool-scope-creep"]
    assert len(hits) == 2, (
        f"expected both cross-file-delegated tools to now be over-flagged "
        f"(hop not followed -> gate not visible), got: {clean.findings}"
    )
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles and "run_shell" in titles
    assert all(f.severity == Severity.P2 for f in hits), (
        "name-only classification (no sink resolvable without the cross-file "
        f"hop) must stay P2, got: {[f.severity for f in hits]}"
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
