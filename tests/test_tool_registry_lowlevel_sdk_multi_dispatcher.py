"""N-vote fix pass (2026-07-23): two fresh-context refuters independently
reproduced a P0 in the first cut of low-level-SDK discovery --
``_extract_low_level_sdk`` rooted EVERY ``Tool()`` construction repo-wide to
whichever ``@server.call_tool()`` handler a nondeterministic file walk found
first. In any repo with more than one low-level dispatcher, a genuinely
tool-reachable sink could be silently mis-rooted and downgraded to
CLI_ONLY/UNCALLED (MEDIUM) instead of the honest pre-patch UNKNOWN (HIGH) --
a confident severity DOWNGRADE, the one forbidden failure direction. The
taint pass (``taint.py``) shares the same bug because it consumes the same
``.node`` roots from ``extract_tool_registry``.

Also reproduced, P1: ``_is_tool_construction``/``_is_call_tool_decorator``
matched on dotted-tail name only -- a LangChain-shaped local ``class Tool``
plus an unrelated ``.call_tool()``-named decorator flipped ``has_tools=True``
and produced a bogus REACHABLE/HIGH grade on a sink the real server never
exposed.

This file covers the fix contract's four required repro shapes (a)-(d).
"""
from pathlib import Path

from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors.base import RepoContext
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Reachability, Confidence, Taint
from mcp_scanner.tool_registry import extract_tool_registry
from mcp_scanner import taint as taint_module


def _by_snippet(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------- #
# (a) Two-server, two-file repo: dispatcher B's sink must root to ITS OWN
# dispatcher, never dispatcher A's -- the exact P0 repro shape.
# --------------------------------------------------------------------- #
def test_two_dispatcher_repo_roots_each_tool_to_its_own_file(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "lowlevel_two_dispatchers"))
    regs = {r.name: r for r in extract_tool_registry(ctx) if r.source == "py-lowlevel-sdk"}
    assert regs["tool_a"].node is not None and regs["tool_a"].node.name == "call_tool_a"
    assert regs["tool_b"].node is not None and regs["tool_b"].node.name == "call_tool_b"
    # The two roots must be genuinely distinct function objects, not the
    # same node shared across both (the P0 bug).
    assert regs["tool_a"].node is not regs["tool_b"].node


def test_dispatcher_b_sink_grades_reachable_not_cli_only(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_two_dispatchers"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"dispatcher-b ')
    assert f.reachability is Reachability.REACHABLE, (
        f"P0 regression: dispatcher B's sink graded {f.reachability!r} -- "
        "must be REACHABLE (its own dispatcher calls it), never CLI_ONLY/"
        "UNCALLED from a mis-rooted repo-wide first-found guess"
    )
    assert f.confidence is Confidence.HIGH


# --------------------------------------------------------------------- #
# (b) Non-MCP Tool/call_tool naming coincidence: has_tools must stay False.
# --------------------------------------------------------------------- #
def test_non_mcp_tool_coincidence_does_not_flip_has_tools(tmp_path):
    (tmp_path / "server.py").write_text(
        "class Tool:\n"
        "    def __init__(self, name, description=''):\n"
        "        self.name = name\n"
        "        self.description = description\n"
        "\n"
        "\n"
        "class dispatcher:\n"
        "    @staticmethod\n"
        "    def call_tool():\n"
        "        def deco(fn):\n"
        "            return fn\n"
        "        return deco\n"
        "\n"
        "\n"
        "_T = Tool(name='not_a_real_tool')\n"
        "\n"
        "\n"
        "@dispatcher.call_tool()\n"
        "def handle(name, arguments):\n"
        "    import os\n"
        "    os.system('coincidence ' + arguments.get('cmd', ''))\n",
        encoding="utf-8",
    )
    ctx, _ = build_context(str(tmp_path))
    regs = extract_tool_registry(ctx)
    assert not regs, f"no `mcp` import anywhere -- registry must stay empty, got {regs}"

    result = scan_repo(str(tmp_path), [ParamInjectionDetector()])
    f = _by_snippet(result, "coincidence")
    assert f.reachability is Reachability.UNKNOWN, (
        "P1 regression: a same-named non-MCP Tool/call_tool coincidence "
        "must not produce a confident grade of any kind"
    )
    assert f.confidence is Confidence.HIGH, "HIGH detector confidence must be preserved, not bumped"


# --------------------------------------------------------------------- #
# (c) Hybrid decorator + low-level in the SAME file: no duplicate/
# conflicting roots between the two discovery sources.
# --------------------------------------------------------------------- #
def test_hybrid_decorator_and_lowlevel_do_not_conflict(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "lowlevel_hybrid"))
    regs = extract_tool_registry(ctx)
    by_source = {r.source: r for r in regs}
    assert "py-decorator" in by_source and "py-lowlevel-sdk" in by_source
    assert by_source["py-decorator"].name == "fastmcp_tool"
    assert by_source["py-decorator"].node.name == "fastmcp_tool"
    assert by_source["py-lowlevel-sdk"].name == "lowlevel_tool"
    assert by_source["py-lowlevel-sdk"].node.name == "call_tool"
    # Distinct roots -- neither source's node was overwritten/shared by the other.
    assert by_source["py-decorator"].node is not by_source["py-lowlevel-sdk"].node


def test_hybrid_repo_both_sinks_reachable_via_their_own_root(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_hybrid"), [ParamInjectionDetector()])
    assert _by_snippet(result, '"fastmcp-path ').reachability is Reachability.REACHABLE
    assert _by_snippet(result, '"lowlevel-path ').reachability is Reachability.REACHABLE


# --------------------------------------------------------------------- #
# (d) Determinism: same repo, reversed file-discovery order -> identical
# registrations. Constructs RepoContext.files directly to bypass the
# scanner.py-level sort and isolate tool_registry.py's own ordering
# independence.
# --------------------------------------------------------------------- #
def test_lowlevel_registration_is_independent_of_file_order(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "lowlevel_two_dispatchers"))
    forward = extract_tool_registry(ctx)

    reversed_ctx = RepoContext(
        root=ctx.root, files=list(reversed(ctx.files)),
        tracked=ctx.tracked, is_git=ctx.is_git,
    )
    backward = extract_tool_registry(reversed_ctx)

    def _key(regs):
        return sorted(
            (r.name, r.source, getattr(r.node, "name", None)) for r in regs
        )

    assert _key(forward) == _key(backward), (
        "P0 regression: registration output (including which handler a tool "
        "roots to) must not depend on file-discovery order"
    )


# --------------------------------------------------------------------- #
# taint.py shares the same registry roots -- the P0 fix must carry through.
# --------------------------------------------------------------------- #
def test_taint_pass_also_roots_dispatcher_b_correctly(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "lowlevel_two_dispatchers"), [ParamInjectionDetector()])
    f = _by_snippet(result, '"dispatcher-b ')
    assert f.taint is Taint.TAINTED, (
        f"P0 regression (taint.py shares tool_registry's .node roots): "
        f"got {f.taint!r}, expected TAINTED -- cmd flows dispatcher_b -> "
        "_run_b -> os.system"
    )
