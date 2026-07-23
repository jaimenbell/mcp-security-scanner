"""Low-level MCP SDK coverage for detector 5 (tool-scope-creep), 2026-07-23.
Before this fix, ``tool_scope_creep.py`` only consumed
``extract_tool_registry``'s ``source == "js-regex"`` entries and re-derived
its own decorator walk directly -- a repo using ONLY the low-level SDK shape
(``Server()`` + a single ``@server.call_tool()`` dispatch function) produced
ZERO findings from this detector regardless of how many ungated mutating
tools it registered.
"""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Severity, Confidence


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_lowlevel_sdk_one_hop_mutating_tool_flagged(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope_lowlevel"), [ToolScopeCreepDetector()])
    assert "tool-scope-creep" in _classes(result)
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles, f"expected 'delete_file' (one-hop sink) flagged, got: {titles}"
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_lowlevel_sdk_direct_branch_mutating_tool_flagged(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope_lowlevel"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "run_shell" in titles, f"expected 'run_shell' (direct sink) flagged, got: {titles}"


def test_lowlevel_sdk_get_status_branch_not_flagged(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope_lowlevel"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "get_status" not in titles


def test_lowlevel_sdk_ambiguous_branch_attributed_to_handler_not_a_tool(fixtures_dir):
    """The `elif name in ('legacy_write', 'legacy_write2')` branch has an
    ungated mutating sink but is genuinely ambiguous -- must be attributed
    to the dispatch handler itself, never guessed at one tool name."""
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope_lowlevel"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    ambiguous_hits = [f for f in hits if "legacy_write" not in f.title and "call_tool" in f.title]
    assert ambiguous_hits, f"expected an unattributed-branch finding, got titles: {[f.title for f in hits]}"
    for f in ambiguous_hits:
        assert "legacy_write" not in f.title
        assert "legacy_write" not in f.detail


def test_lowlevel_sdk_shared_pre_dispatch_gate_quiets_all_branches(fixtures_dir):
    """clean_tool_scope_lowlevel has a shared `if not check_permission(name):
    raise` guard before the if/elif chain -- every mutating branch in the
    same handler must be treated as gated."""
    result = scan_repo(str(fixtures_dir / "clean_tool_scope_lowlevel"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    assert hits == [], f"shared pre-dispatch gate must quiet every branch, got: {[(f.title, f.file, f.line) for f in hits]}"


def test_lowlevel_sdk_ambiguous_file_skipped_but_valid_sibling_still_flagged(fixtures_dir):
    """Reuses tests/fixtures/lowlevel_mixed_ambiguous (built for the
    reachability fix): x_ambiguous.py has TWO @server.call_tool() handlers
    in one file -- genuinely ambiguous, must be skipped entirely (never
    guess a root), even though its helper (_run_x) has an ungated os.system
    sink. y_valid.py in the SAME repo has exactly one call_tool handler with
    no if/elif dispatch shape at all -- its ungated sink must still be
    flagged, attributed to the dispatch handler (no per-tool attribution
    possible without a dispatch chain)."""
    result = scan_repo(str(fixtures_dir / "lowlevel_mixed_ambiguous"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    assert not any("x_ambiguous.py" in f.file for f in hits), (
        f"ambiguous-dispatcher file must never guess a root, got: {[(f.file, f.title) for f in hits]}"
    )
    assert any("y_valid.py" in f.file for f in hits), (
        f"the unambiguous sibling file's ungated sink must still be flagged, got: {result.findings}"
    )


# --------------------------------------------------------------------- #
# P0-1 N-vote fix: gate detection must be per-branch, not whole-handler-text
# --------------------------------------------------------------------- #
def test_p0_1_sibling_branch_gate_does_not_silence_ungated_sibling(fixtures_dir):
    """A gate hint ("is_authorized") inside the read_file branch must not
    silence delete_file's own genuinely ungated os.remove() sink in the same
    handler -- the exact false negative the N-vote refuter reproduced live
    against the previous whole-handler-text `_node_has_gate` check."""
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope_lowlevel_sibling_gate"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles, (
        f"delete_file's ungated sink must still be flagged despite the sibling "
        f"branch's gate hint, got: {[f.title for f in hits]}"
    )
    assert "read_file" not in titles, f"read_file is gated and non-mutating, must stay quiet, got: {titles}"


# --------------------------------------------------------------------- #
# P3 N-vote fix: detector-level end-to-end proof for the negated-guard shape
# --------------------------------------------------------------------- #
def test_p3_negated_guard_shape_still_flags_via_whole_handler_fallback(fixtures_dir):
    """rag-mcp's real `if name != "x": ... else: ...` shape isn't recognized
    as attributable dispatch, but the ungated mutating sink in the else-body
    must still surface via the whole-handler fallback."""
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope_lowlevel_negated_guard"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    assert hits, f"expected the else-body os.remove() sink to be flagged, got: {result.findings}"
    for f in hits:
        assert "delete_file" not in f.title, (
            f"a `!=`-guarded shape must not be guessed at one tool name, got: {f.title}"
        )
        assert "call_tool" in f.title or "dispatch handler" in f.title
