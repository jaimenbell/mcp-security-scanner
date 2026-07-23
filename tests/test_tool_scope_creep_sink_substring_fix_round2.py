"""sink-substring-fix lane, round-2 N-vote fix pass (2026-07-23).

Both refuters REFUTED the round-1 fix (commit 2df84e1) with live repros:
gating the `_MUTATING_SINK_SHORT` fallback on `"." in name` (a rendered-
string syntax-shape proxy) rather than resolving what the callee actually
is broke real detection on both sides:

  P0 (refuter A): blanket-excluded EVERY bare Name call, including a bare
  call to a REAL sink imported directly (`from os import remove`, `from
  shutil import rmtree`, `from subprocess import run`) -- base caught all
  of these, round 1 silenced them completely.

  P1 (refuter B): even for real attribute calls, `_dotted` collapses to the
  bare leaf whenever the receiver is a `Call`/`Subscript` (not a plain
  `Name`) -- `Path(x).unlink()`, `requests.Session().post(url)`,
  `get_proc().run(cmd)` all render with no "." at all, so round 1's gate
  silently missed all three despite them being genuine attribute-call sink
  shapes.

Round 2 replaces the syntax-shape proxy with RESOLUTION: `_SinkFileCtx`
(module aliases, direct stdlib-sink imports, repo-internal bare names,
built via `_build_sink_file_ctx` from machinery this repo already owns --
`_build_import_map`, the same-file function index) and structural
`isinstance(call.func, ast.Attribute)` gating instead of `"." in name`.
See `tool_scope_creep.py`'s `_SinkFileCtx`/`_resolved_sink_name` docstrings
for the full resolution-order rationale.

Every fixture below is a LIVE repro from the N-vote report, pinned as a
permanent regression test against round 1 (commit 2df84e1, where every one
of these assertions would have failed -- verified manually against that
commit's checked-out file during this round-2 pass)."""
from __future__ import annotations

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.detectors.tool_scope_creep import (
    _is_mutating_sink_call,
    _is_high_risk_sink_call,
    _SinkFileCtx,
    _SINK_DOTTED_EXACT,
)
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
# P0 (refuter A): 4 ungated mutating tools, each a direct bare-imported
# real sink. Round 1: 0 flagged (blanket bare-call exclusion). Base and
# round 2: all 4 flagged, P1/HIGH (os.remove/shutil.rmtree are
# unconditional high-risk; subprocess.run/call both pass shell=True).
# --------------------------------------------------------------------- #
def test_p0_bare_imported_real_sinks_all_four_flagged_p1_high(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_bare_imported_sinks"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    for tool in ("sync_status", "refresh_cache", "check_state", "fetch_report"):
        assert tool in titles, f"expected '{tool}' flagged (bare-imported real sink), got: {titles}"
    matching = [f for f in hits if any(t in f.title for t in ("sync_status", "refresh_cache", "check_state", "fetch_report"))]
    assert all(f.severity == Severity.P1 for f in matching), (
        f"all 4 bare-imported real sinks must be P1/HIGH, got: {[(f.title, f.severity, f.confidence) for f in matching]}"
    )
    assert all(f.confidence == Confidence.HIGH for f in matching)


# --------------------------------------------------------------------- #
# P1 (refuter B): 3 attribute-call sinks whose receiver is a Call (not a
# plain Name) -- _dotted collapses all three to a bare leaf. Round 1: 0
# flagged. Base and round 2: all 3 flagged (structural isinstance(...,
# ast.Attribute) gate, not "." presence).
# --------------------------------------------------------------------- #
def test_p1_call_receiver_attribute_sinks_all_three_flagged(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_call_receiver_attr_sinks"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    titles = " ".join(f.title for f in hits)
    for tool in ("check_file", "notify_service", "poll_worker"):
        assert tool in titles, (
            f"expected '{tool}' flagged (Call-receiver attribute sink -- "
            f"_dotted collapses to a bare leaf, must still be caught "
            f"structurally), got: {titles}"
        )


# --------------------------------------------------------------------- #
# Refuter A, item 4: aliased-import severity calibration. `import
# subprocess as sp; sp.run(...)` must canonicalize through the module
# alias for the shell=True axis, same as the plain spelling.
# --------------------------------------------------------------------- #
def test_aliased_subprocess_shell_true_calibration_resolved(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_aliased_subprocess"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    probe_hits = [f for f in hits if "probe_status" in f.title]
    check_hits = [f for f in hits if "check_task" in f.title]
    assert probe_hits, f"expected probe_status flagged, got: {[f.title for f in hits]}"
    assert check_hits, f"expected check_task flagged, got: {[f.title for f in hits]}"
    assert all(f.severity == Severity.P2 for f in probe_hits), (
        f"aliased sp.run(...) without shell=True must calibrate to P2 "
        f"(same as the un-aliased spelling), got: {[(f.severity, f.confidence) for f in probe_hits]}"
    )
    assert all(f.severity == Severity.P1 for f in check_hits), (
        f"aliased sp.run(..., shell=True) must stay P1/HIGH, got: "
        f"{[(f.severity, f.confidence) for f in check_hits]}"
    )
    assert all(f.confidence == Confidence.HIGH for f in check_hits)


# --------------------------------------------------------------------- #
# Refuter B, P2: the two-hop-miss-at-zero-findings shape (the REAL
# vllm-ops-mcp shape) previously had no regression guard in this repo.
# Pinned here, permanently, with the disclosure in the fixture's own
# docstring.
# --------------------------------------------------------------------- #
def test_two_hop_probe_miss_is_zero_findings_disclosed(fixtures_dir):
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_two_hop_probe_miss"),
        [ToolScopeCreepDetector()],
    )
    hits = [f for f in result.findings if f.vuln_class == "tool-scope-creep"]
    assert hits == [], (
        f"a two-hop-deep real sink (tool -> one resolved hop -> a bare "
        f"repo-internal call -> the real sink one hop further) is an "
        f"honest, disclosed miss of this detector's one-hop-only bound -- "
        f"never a guess. got: {[(f.title, f.file, f.line) for f in hits]}"
    )


# --------------------------------------------------------------------- #
# Item 3: exact-set enrichment -- getoutput/getstatusoutput recognized;
# dead lowercase "subprocess.popen" entry removed.
# --------------------------------------------------------------------- #
def test_subprocess_getoutput_and_getstatusoutput_recognized_as_sinks():
    ctx = _SinkFileCtx(symbol_aliases={"getoutput": "subprocess.getoutput"})
    bare = _call_from_src("getoutput(cmd)")
    assert _is_mutating_sink_call(bare, ctx) is True, (
        "subprocess.getoutput (bare-imported) must be recognized as a sink"
    )
    attr = _call_from_src("subprocess.getstatusoutput(cmd)")
    assert _is_mutating_sink_call(attr) is True, (
        "subprocess.getstatusoutput must be recognized as a sink"
    )
    # always shell-interpreted (no `shell=` kwarg exists on either) -- must
    # be unconditionally high-risk, never calibrated down.
    assert _is_high_risk_sink_call(attr) is True


def test_dead_lowercase_subprocess_popen_entry_removed():
    assert "subprocess.popen" not in _SINK_DOTTED_EXACT, (
        "subprocess.popen (lowercase) is not a real callable -- os.popen is "
        "the real one and stays in the set; this dead entry must be removed"
    )


# --------------------------------------------------------------------- #
# Converge-pass P2 perf fix (refuter B2, 2026-07-23): the per-candidate-file
# _SinkFileCtx cache must be REPO-WIDE (built once in run()), not local to
# _inspect_body (which runs once per TOOL) -- a shared cross-file helper's
# context (3 full AST walks to build) must not be rebuilt for every tool
# that references it. `clean_tool_scope_groups_import` is the ideal existing
# fixture for this: TWO tools (delete_file_tool, run_shell_tool) both
# one-hop-delegate to the SAME file, groups/write.py.
# --------------------------------------------------------------------- #
def test_shared_cross_file_helper_ctx_built_once_not_per_tool(fixtures_dir, monkeypatch):
    import mcp_scanner.detectors.tool_scope_creep as tsc_mod

    calls: list[str] = []
    real_builder = tsc_mod._build_sink_file_ctx

    def counting_builder(f, files_by_rel=None, local_func_names=None):
        calls.append(f.rel)
        return real_builder(f, files_by_rel, local_func_names=local_func_names)

    monkeypatch.setattr(tsc_mod, "_build_sink_file_ctx", counting_builder)

    result = scan_repo(str(fixtures_dir / "clean_tool_scope_groups_import"), [ToolScopeCreepDetector()])
    assert result.findings == []  # sanity: fixture is still quiet (gated)

    write_py_calls = [c for c in calls if c.endswith("groups/write.py") or c.endswith("groups\\write.py")]
    assert len(write_py_calls) == 1, (
        f"groups/write.py's _SinkFileCtx must be built exactly ONCE across "
        f"both tools that reference it (delete_file_tool, run_shell_tool), "
        f"not once per tool -- got {len(write_py_calls)} builds. Full call "
        f"log: {calls}"
    )
