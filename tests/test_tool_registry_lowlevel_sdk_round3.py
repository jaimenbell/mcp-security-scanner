"""Round-3 N-vote fix (2026-07-23): Opus final-verify on round-2 (8011818)
confirmed both refuter P0/P1 killed, but BLOCKED on two further confident
severity-downgrade shapes, both reproduced:

(a) SPLIT SERVER -- the common declaration-module / dispatch-module split.
    ``declare.py`` has ``Tool(...)`` + ``@server.list_tools()`` and NO
    ``call_tool``; round-2's list_tools fallback rooted the tool at the
    list_tools handler itself, which returns metadata and never executes
    tool logic -- semantically wrong, not "the honest UNKNOWN behavior" as
    claimed. Real dispatch (``@server.call_tool()`` + the sink) lives in a
    separate file, ``dispatch.py``. Result at 8011818: CLI_ONLY/MEDIUM.
    Base (pre-any-fix) c295330: UNKNOWN/HIGH.

(b) MIXED AMBIGUOUS + VALID -- the disclosed residual, reproduced: a
    genuinely ambiguous dispatcher (two ``@server.call_tool()`` in one
    file, node=None) sits in the SAME REPO as an unrelated file with a
    perfectly valid root. reachability.py's ``has_tools``/
    ``have_py_handlers`` are computed repo-wide, so the valid root
    "unlocks" confident CLI_ONLY/UNCALLED grading for the un-rooted tool's
    findings too, even though this pass never walked its real dispatcher.

Fix: reachability.py's grade_result computes ``unrooted_lowlevel`` (any
``py-lowlevel-sdk`` registration with ``node=None``) and treats it exactly
like ``dynamic_dispatch_present`` -- the CLI_ONLY/UNCALLED branch returns
UNKNOWN instead. tool_registry.py's list_tools fallback is removed outright
(zero call_tool handlers in a file -> node=None, full stop, no fallback).
"""
from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Reachability, Confidence, Taint
from mcp_scanner.tool_registry import extract_tool_registry


def _by_snippet(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------- #
# (a) Split-server shape
# --------------------------------------------------------------------- #
def test_split_server_registration_has_no_root(fixtures_dir):
    """The list_tools fallback is gone: declare.py's Tool() construction
    must register (has_tools stays True) but with node=None -- never the
    list_tools handler itself."""
    ctx, _ = build_context(str(fixtures_dir / "lowlevel_split_server"))
    regs = [r for r in extract_tool_registry(ctx) if r.source == "py-lowlevel-sdk"]
    assert len(regs) == 1
    assert regs[0].name == "split_tool"
    assert regs[0].node is None, (
        "round-2 regression: list_tools fallback must be removed -- "
        f"got node={regs[0].node!r}"
    )


def test_split_server_sink_grades_unknown_not_cli_only(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_split_server"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"split-dispatch ')
    assert f.reachability is Reachability.UNKNOWN, (
        f"round-3 regression: split-server sink graded {f.reachability!r} -- "
        "must be UNKNOWN (this pass never walked the real dispatcher in a "
        "different file), never a confident CLI_ONLY/UNCALLED downgrade"
    )
    assert f.confidence is Confidence.HIGH, "HIGH detector confidence must be preserved, not lowered"


def test_split_server_sink_taint_stays_unknown(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_split_server"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"split-dispatch ')
    assert f.taint is Taint.UNKNOWN, (
        f"no confident wrong taint verdict allowed here -- got {f.taint!r}"
    )


# --------------------------------------------------------------------- #
# (b) Mixed ambiguous + valid dispatcher shape (the disclosed residual)
# --------------------------------------------------------------------- #
def test_mixed_repo_ambiguous_tool_has_no_root(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "lowlevel_mixed_ambiguous"))
    regs = {r.name: r for r in extract_tool_registry(ctx) if r.source == "py-lowlevel-sdk"}
    assert regs["ambiguous_tool"].node is None
    assert regs["valid_tool"].node is not None
    assert regs["valid_tool"].node.name == "call_tool_y"


def test_mixed_repo_ambiguous_sink_grades_unknown_not_cli_only(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_mixed_ambiguous"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"ambiguous-dispatch ')
    assert f.reachability is Reachability.UNKNOWN, (
        f"round-3 regression (disclosed residual): ambiguous-dispatcher "
        f"sink graded {f.reachability!r} -- a valid root ELSEWHERE in the "
        "repo must not unlock confident grading for this un-rooted tool"
    )
    assert f.confidence is Confidence.HIGH


def test_mixed_repo_ambiguous_sink_taint_stays_unknown(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_mixed_ambiguous"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"ambiguous-dispatch ')
    assert f.taint is Taint.UNKNOWN


def test_mixed_repo_valid_sink_still_grades_reachable(fixtures_dir):
    """The fix must not overcorrect: a genuinely reachable sink elsewhere in
    the same repo (via a valid root) must still grade REACHABLE --
    unrooted_lowlevel only gates the NOT-reachable branch."""
    result = scan_repo(str(fixtures_dir / "lowlevel_mixed_ambiguous"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"valid-dispatch ')
    assert f.reachability is Reachability.REACHABLE
    assert f.confidence is Confidence.HIGH
