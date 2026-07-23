"""Low-level MCP SDK tool discovery (2026-07-23).

``extract_tool_registry`` only recognized decorator-style registration
(``@x.tool()``), so repos using the low-level MCP SDK pattern -- ``Server()``
+ a ``@server.list_tools()`` handler returning ``types.Tool(...)`` objects,
dispatched via ``@server.call_tool()`` -- got ``has_tools=False``, which
cascades to blanket-UNKNOWN reachability for every finding in those repos.
rag-mcp's real ``rag_mcp/server.py`` is a live in-fleet example of this shape.

This file is the failing-first TDD fixture test; see ``tool_registry.py``'s
``_extract_low_level_sdk`` for the fix.
"""
import tempfile
from pathlib import Path

from mcp_scanner.scanner import scan_repo, build_context
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Reachability
from mcp_scanner.tool_registry import extract_tool_registry


def _by_snippet(result, needle):
    hits = [f for f in result.findings if needle in f.snippet]
    assert len(hits) == 1, f"expected exactly one finding for {needle!r}, got {hits}"
    return hits[0]


# --------------------------------------------------------------------- #
# extract_tool_registry: the low-level Server()/list_tools/types.Tool shape
# --------------------------------------------------------------------- #
def test_extractor_finds_lowlevel_sdk_tool(fixtures_dir):
    ctx, _ = build_context(str(fixtures_dir / "reachability_lowlevel_sdk"))
    regs = extract_tool_registry(ctx)
    names = {r.name for r in regs if r.source == "py-lowlevel-sdk"}
    assert "search_knowledge" in names


def test_lowlevel_sdk_registration_has_a_handler_root(fixtures_dir):
    """The registry entry must carry the ``@server.call_tool()`` dispatch
    function as its ``node`` -- otherwise reachability grading can flip
    ``has_tools`` True without gaining a real call-graph root (still UNKNOWN
    everywhere, just for a different reason)."""
    ctx, _ = build_context(str(fixtures_dir / "reachability_lowlevel_sdk"))
    regs = extract_tool_registry(ctx)
    lowlevel = [r for r in regs if r.source == "py-lowlevel-sdk"]
    assert lowlevel, "expected at least one py-lowlevel-sdk registration"
    assert all(r.node is not None for r in lowlevel)
    assert all(getattr(r.node, "name", None) == "call_tool" for r in lowlevel)


def test_bare_tool_ctor_import_form_is_harvested():
    """``from mcp.types import Tool`` + bare ``Tool(name=...)`` (no ``types.``
    prefix) must be recognized the same as ``types.Tool(...)``."""
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "server.py").write_text(
            "from mcp.types import Tool\n"
            "from mcp.server import Server\n"
            "server = Server('demo')\n"
            "_T = Tool(name='bare_form_tool', description='x', inputSchema={})\n"
            "\n"
            "@server.list_tools()\n"
            "async def list_tools():\n"
            "    return [_T]\n",
            encoding="utf-8",
        )
        ctx, _ = build_context(d)
        regs = extract_tool_registry(ctx)
        names = {r.name for r in regs if r.source == "py-lowlevel-sdk"}
        assert "bare_form_tool" in names


# --------------------------------------------------------------------- #
# has_tools flips True -- the actual bug: a repo using only this shape used
# to grade every finding UNKNOWN regardless of reachability.
# --------------------------------------------------------------------- #
def test_lowlevel_sdk_repo_has_tools_true(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_lowlevel_sdk"), [ParamInjectionDetector()])
    assert result.findings, "sanity: the sinks should still be flagged"
    assert not all(f.reachability is Reachability.UNKNOWN for f in result.findings), (
        "has_tools should be True for a low-level-SDK repo -- reachability "
        "grading must not blanket-UNKNOWN every finding"
    )


# --------------------------------------------------------------------- #
# Real reachability grading through the call_tool dispatch root.
# --------------------------------------------------------------------- #
def test_sink_reachable_through_call_tool_dispatch(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_lowlevel_sdk"), [ParamInjectionDetector()])
    assert _by_snippet(result, '"search ').reachability is Reachability.REACHABLE


def test_dead_helper_stays_uncalled(fixtures_dir):
    result = scan_repo(str(fixtures_dir / "reachability_lowlevel_sdk"), [ParamInjectionDetector()])
    assert _by_snippet(result, '"dead-lowlevel ').reachability is Reachability.UNCALLED
