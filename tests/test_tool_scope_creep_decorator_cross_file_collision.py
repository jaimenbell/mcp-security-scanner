"""Decorator-path P0 N-vote regression (2026-07-23, closing the README's
named follow-up): the pre-existing decorator-registered path in
``tool_scope_creep.py`` built its ``func_index``/``gated_names`` REPO-WIDE by
bare short function name in ``run()``. An unrelated, never-imported,
same-named gated helper elsewhere in the repo could silence a genuinely
ungated decorator-registered mutating tool -- a false NEGATIVE on this
detector's primary target class (worse direction than a false positive).

Live repro fixture: ``vuln_tool_scope_cross_file_gate_collision`` -- an
ungated ``delete_file`` tool one-hop-delegates to its own local, genuinely
ungated ``_cleanup`` (real ``os.remove`` sink); an unrelated file elsewhere
in the same repo has its own same-named ``_cleanup`` that happens to carry
a real gate check. Before the same-file-only fix, this produced ZERO
findings."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Severity, Confidence


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_decorator_path_cross_file_same_name_gate_does_not_silence_ungated_tool(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_cross_file_gate_collision"),
        [ToolScopeCreepDetector()],
    )
    assert "tool-scope-creep" in _classes(result), (
        "delete_file_tool's genuinely ungated os.remove() sink (one hop via "
        "its own local _cleanup helper) must be flagged -- an unrelated "
        "same-named _cleanup elsewhere in the repo that happens to be gated "
        "must NOT silence it via a repo-wide-by-name gate index, got: "
        f"{[(f.vuln_class, f.file, f.line) for f in result.findings]}"
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "delete_file" in titles, f"expected delete_file flagged, got: {titles}"
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)
