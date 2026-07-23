"""Round-2 N-vote fix pass (2026-07-23, later same day): the round-1
same-file-only fix (closing the decorator-path repo-wide gate-index
collision) was itself proven to over-correct by two live refuter repros:

  P0-1: same-file scoping severed the cross-file SINK hop, not just the gate
        hop -- a non-mutating-named tool delegating to a real, genuinely
        ungated sink in a separate, EXPLICITLY IMPORTED file went from
        correctly-flagged to total silence (0 findings).
  P0-2: the same-file gate index still unioned bare method names across
        DIFFERENT classes in one file -- a genuinely ungated method could
        still be silenced by an unrelated same-named gated method on a
        different class in the same file.

Fix: a bounded, one-hop, import-aware resolver. An explicit same-repo
import (`from x.y import z` / `from .pkg import submodule` / `import mod`)
is followed for BOTH sink detection and gate credit; a same-file
class-qualified call (`ClassName().method(...)`) is cheaply disambiguated
to the exact class's own method; anything else falls back to the same-file
bare-name heuristic, with an ambiguity rule when multiple same-named
same-file candidates disagree on gate status (credited only if unanimous).
"""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Severity, Confidence


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_p0_1_cross_file_sink_via_explicit_import_is_flagged(fixtures_dir):
    """sync_repo (non-mutating name) one-hop-delegates via `from . import
    write` to write.py's genuinely ungated `do_thing` (real subprocess.run
    sink). Must be flagged P1/HIGH -- the import-aware resolver follows the
    explicit relative import for sink detection, not just gate credit."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_cross_file_sink_import"),
        [ToolScopeCreepDetector()],
    )
    assert "tool-scope-creep" in _classes(result), (
        f"expected sync_repo's cross-file sink to be flagged, got: {result.findings}"
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "sync_repo" in titles, f"expected sync_repo flagged, got: {titles}"
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_p0_2_same_file_class_qualified_call_disambiguated(fixtures_dir):
    """purge_report_tool calls ReportHandlers().helper -- must resolve
    EXACTLY to ReportHandlers.helper (ungated, real os.remove sink), never
    credited by AdminHandlers.helper's unrelated @gated_write."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_same_file_class_collision"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "purge_report" in titles, (
        f"expected purge_report flagged (ReportHandlers.helper is genuinely "
        f"ungated), got: {result.findings}"
    )
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_github_mcp_shape_groups_import_stays_quiet(fixtures_dir):
    """The real dominant fleet pattern -- thin @mcp.tool() wrapper importing
    a gated helper from a separate groups/*.py submodule via `from .groups
    import write` (github-mcp's/desktop-mcp's actual shape) -- must resolve
    the gate via the explicit import and stay quiet."""
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_groups_import"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        f"properly-gated groups/*.py import delegation must not be flagged, "
        f"got: {[(f.vuln_class, f.file, f.line) for f in result.findings]}"
    )


def test_unresolvable_external_hop_residual_is_disclosed_miss(fixtures_dir):
    """sync_data (non-mutating name) delegates to a helper imported from a
    third-party package not present in this repo at all -- no file to
    resolve to. This is the disclosed residual: an unresolvable hop leaves
    a non-mutating-named tool's sink un-followed. Pinned as intentional,
    not a bug -- see the module docstring / README wording for this exact
    residual."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_unresolvable_external_hop"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        f"an unresolvable (non-repo) import hop on a non-mutating-named tool "
        f"is a disclosed miss, not a flag -- got: {result.findings}"
    )


def test_cross_file_gate_collision_repro_still_fixed(fixtures_dir):
    """Round-1 regression must still hold under the round-2 resolver: the
    original repo-wide bare-name gate-index collision repro must still be
    flagged (delete_file's own local, same-file ungated helper must never
    be silenced by an unrelated same-named gated helper in a different,
    never-imported file elsewhere in the repo)."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_cross_file_gate_collision"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles, f"expected delete_file flagged, got: {titles}"
