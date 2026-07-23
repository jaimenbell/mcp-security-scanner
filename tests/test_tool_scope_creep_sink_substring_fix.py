"""sink-substring-fix lane (2026-07-23): `_is_mutating_sink_call` used to
classify a call as a dangerous sink via a bare SUBSTRING test on the call's
own dotted/bare name -- `if "subprocess" in name`. A helper function whose
NAME merely CONTAINS a sink word (e.g. `_run_subprocess`) matched that test
even when its body never touches the real `subprocess` module, and the
`_MUTATING_SINK_SHORT` fallback had the same class of bug one level down:
exact-equality on a call's bare short name (`run`, `post`, ...) regardless of
whether the call was even an attribute access on anything -- a bare
user-defined function literally named `run` matched it too.

Live motivating case (verified twice, round-2 lane + Opus final verify):
vllm-ops-mcp's `get_gpu_status` / `get_service_status` / `get_serve_config`
each one-hop-delegate to `_run_subprocess`, a helper whose OWN name merely
contains "subprocess" -- 3 false P1/HIGH findings, reproduced byte-identical
at 4a63544 and 15b5460.

This file pins the fix's three required cases plus the attribute-only
short-name fix, and documents the chosen severity-calibration semantics for
the genuinely-true "subprocess reached via one-hop, no shell=True" case (see
tool_scope_creep.py's module docstring, "round 3" section, for the full
rationale)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.detectors.tool_scope_creep import _is_mutating_sink_call
from mcp_scanner.models import Severity, Confidence

import ast


def _classes(r):
    return {f.vuln_class for f in r.findings}


def _call_from_src(src: str) -> ast.Call:
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return node
    raise AssertionError(f"no call found in: {src}")


# --------------------------------------------------------------------- #
# (a) helper literally named `_run_subprocess` with a BENIGN body (no real
#     sink) -- must NOT flag. This is the direct substring-bug repro: before
#     the fix, the bare call `_run_subprocess(1, 2)` matched
#     `"subprocess" in "_run_subprocess"` regardless of the helper's body.
# --------------------------------------------------------------------- #
def test_helper_named_subprocess_with_benign_body_not_flagged(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_subprocess_name_no_real_sink"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        f"a helper named '_run_subprocess' with a benign (non-sink) body must "
        f"never be treated as a mutating sink merely because of its NAME, got: "
        f"{[(f.title, f.file, f.line) for f in result.findings]}"
    )


# --------------------------------------------------------------------- #
# (b) helper wrapping a REAL subprocess.run(...) call, no shell=True (fixed
#     argv list) -- the exact live vllm-ops-mcp shape. Pinned semantics:
#     flagged (never suppressed -- matches the round-2-pinned
#     vuln_tool_scope_cross_file_sink_import precedent that a real one-hop
#     sink on a non-mutating-named tool must surface), but calibrated to
#     P2/MEDIUM rather than P1/HIGH -- a fixed argv list with no shell
#     metacharacter interpretation is materially lower-risk than the
#     shell=True case.
# --------------------------------------------------------------------- #
def test_subprocess_readonly_probe_flagged_but_calibrated_p2(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_subprocess_readonly_probe"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    assert "get_gpu_status" in titles, (
        f"a real one-hop-resolved subprocess.run sink must still surface "
        f"(never fully suppressed), got: {[f.title for f in result.findings]}"
    )
    gpu_hits = [f for f in hits if "get_gpu_status" in f.title]
    # severity is untouched by the post-detector reachability/taint grading
    # passes (scan_repo's grade_result/grade_taint only nudge CONFIDENCE --
    # see mcp_scanner/reachability.py's `_RAISE`/`_LOWER` tables), so this is
    # a direct, pipeline-level proof of the P1 -> P2 calibration.
    assert all(f.severity == Severity.P2 for f in gpu_hits), (
        f"a shell=True-free, fixed-argv subprocess.run reached only via a "
        f"one-hop helper must be calibrated to P2, not P1, got: "
        f"{[(f.severity, f.confidence) for f in gpu_hits]}"
    )


def test_subprocess_readonly_probe_detector_own_confidence_is_medium(fixtures_dir):
    """The detector's OWN confidence signal (before scan_repo's separate,
    orthogonal reachability-based grading pass raises MEDIUM -> HIGH for any
    finding on a directly-reachable MCP tool -- see
    `mcp_scanner/reachability.py`'s `_RAISE` table, unrelated to this lane)
    is MEDIUM for the calibrated-down case. Checked directly against
    `ToolScopeCreepDetector.run()`, bypassing `scan_repo`'s enrichment
    passes, so this stays a clean unit check on `_is_high_risk_sink_call`'s
    calibration rather than conflating it with reachability grading."""
    ctx, _ = build_context(str(fixtures_dir / "vuln_tool_scope_subprocess_readonly_probe"))
    findings = ToolScopeCreepDetector().run(ctx)
    gpu_hits = [f for f in findings if "get_gpu_status" in f.title]
    assert gpu_hits, f"expected get_gpu_status flagged, got: {[f.title for f in findings]}"
    assert all(f.confidence == Confidence.MEDIUM for f in gpu_hits), (
        f"expected the detector's own confidence to be MEDIUM for the "
        f"calibrated-down finding, got: {[(f.severity, f.confidence) for f in gpu_hits]}"
    )


# --------------------------------------------------------------------- #
# (c) direct subprocess.run(cmd, shell=True) in the tool's own body --
#     UNCHANGED from today: still P1/HIGH. Regression-pins the existing
#     vuln_tool_scope fixture/test so the shell=True severity axis never
#     accidentally weakens the real, already-correct high-risk case.
# --------------------------------------------------------------------- #
def test_direct_shell_true_subprocess_call_stays_p1_high(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "vuln_tool_scope"), [ToolScopeCreepDetector()])
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    run_shell_hits = [f for f in hits if "run_shell" in f.title]
    assert run_shell_hits, f"expected run_shell flagged, got: {[f.title for f in hits]}"
    assert all(f.severity == Severity.P1 for f in run_shell_hits)
    assert all(f.confidence == Confidence.HIGH for f in run_shell_hits)


# --------------------------------------------------------------------- #
# Cross-file one-hop shell=True sink (round-2 pinned fixture) must ALSO stay
# P1/HIGH -- the shell=True calibration axis is orthogonal to direct-vs-
# one-hop reachability, never a second silent regression vector.
# --------------------------------------------------------------------- #
def test_cross_file_one_hop_shell_true_sink_stays_p1_high(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_cross_file_sink_import"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


# --------------------------------------------------------------------- #
# Round-2 N-vote fix pass (2026-07-23): a bare call must be RESOLVED, never
# blanket-included or blanket-excluded. With a ctx that resolves "run" to a
# repo-internal function, it is NOT a direct sink (the hop machinery
# inspects that function's real body elsewhere). With no resolution
# available at all (ctx=None, or a ctx that doesn't know this name), the
# bare call falls through to the over-flag-safe short-name fallback --
# restoring base's pre-existing catch on a shape this pass can't prove
# safe (refuter A's exact P0 complaint against the round-1 blanket
# exclusion). An attribute call (`x.run(...)`) always matches regardless.
# --------------------------------------------------------------------- #
def test_bare_call_resolved_via_ctx_vs_unresolvable():
    from mcp_scanner.detectors.tool_scope_creep import _SinkFileCtx

    bare = _call_from_src("run(1, 2)")
    resolved_ctx = _SinkFileCtx(local_names=frozenset({"run"}))
    assert _is_mutating_sink_call(bare, resolved_ctx) is False, (
        "a bare call resolved (via ctx) to a repo-internal function must "
        "not be classified as a mutating sink by itself"
    )
    assert _is_mutating_sink_call(bare) is True, (
        "a bare call with NO resolution available at all must over-flag "
        "(restores base's pre-existing catch -- refuter A's P0)"
    )
    attr = _call_from_src("subprocess.run(cmd, shell=True)")
    assert _is_mutating_sink_call(attr) is True, (
        "subprocess.run(...) as a real attribute call must still be a sink"
    )


# --------------------------------------------------------------------- #
# End-to-end: the read-only-tool-not-classified-mutating case from the
# original test suite must still hold after these changes (no regression to
# the baseline non-mutating path).
# --------------------------------------------------------------------- #
def test_readonly_named_tool_with_benign_helper_still_quiet():
    det = ToolScopeCreepDetector()
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.py"
        p.write_text(
            "from fastmcp import FastMCP\n"
            "mcp = FastMCP('x')\n\n"
            "def _run_subprocess(a, b):\n"
            "    return a + b\n\n"
            "@mcp.tool(name='get_status')\n"
            "async def get_status_tool() -> dict:\n"
            "    return {'ok': True, 'total': _run_subprocess(1, 2)}\n",
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        findings = det.run(ctx)
        assert findings == []
