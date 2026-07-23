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


def test_cross_file_gate_via_explicit_import_stays_quiet(clean):
    """`clean_tool_scope` models a thin @mcp.tool() wrapper in server.py that
    delegates via an explicit `from . import write` to a gated helper in a
    SEPARATE file, write.py. History (2026-07-23, both same day):

      round 1 (closing the README's named follow-up) found this quiet only
      because the decorator path's func_index/gated_names were built
      REPO-WIDE by bare short function name -- an N-vote refuter proved that
      same repo-wide index let an unrelated, never-imported, same-named
      gated helper elsewhere in the repo silence a genuinely UNGATED tool
      (false negative). Scoping same-file-only fixed that, but as an
      interim side effect also stopped following THIS fixture's genuinely
      gated cross-file hop (temporarily over-flagged, disclosed at the
      time).

      round 2 (same day, second N-vote pass) added a bounded, one-hop,
      IMPORT-AWARE resolver: an explicit same-repo import like `from .
      import write` is followed for gate credit (never a repo-wide guess --
      exactly one target file, resolved from the import statement itself).
      This fixture's tools are correctly quiet again -- not a regression
      back to the original bug, because resolution is import-provenance-
      gated, not bare-name-matched repo-wide."""
    assert clean.findings == [], (
        f"a cross-file gate reached via an explicit, statically-resolvable "
        f"same-repo import must not be flagged, got: "
        f"{[(f.vuln_class, f.file, f.line) for f in clean.findings]}"
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
