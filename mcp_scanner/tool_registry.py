"""Shared MCP tool-registry extraction.

A single source of truth for "which functions in this repo are registered as
MCP tools", used by two consumers:

  * ``detectors/tool_scope_creep.py`` — was carrying its own private copies of
    the decorator-shape helpers; they now live here so there is one parser, not
    two that can drift.
  * ``reachability.py`` — needs the registered tool handlers as the roots of
    its call-graph reachability grading.

Discovery covers the three dominant real-world shapes in this fleet:

  1. **Python FastMCP decorators** — ``@mcp.tool()`` / ``@server.tool()`` (and
     any ``<x>.tool`` attribute call/name), parsed from the AST.
  2. **JS/TS registrations** — ``server.tool("name", ...)`` /
     ``<x>.tool(...)`` calls, matched at regex level (the JS surface has no AST
     path in this scanner, stated honestly on every report).
  3. **Python low-level MCP SDK** (2026-07-23) — ``Server()`` + a
     ``@server.list_tools()`` handler returning ``types.Tool(...)`` / bare
     ``Tool(...)`` objects, dispatched via a single ``@server.call_tool()``
     function. rag-mcp's real ``rag_mcp/server.py`` is the live in-fleet
     example this was missing before: no decorator-per-tool exists in this
     shape, so the FastMCP scan above sees nothing, and this repo shape
     previously registered zero tools (``has_tools=False``), cascading to
     blanket-UNKNOWN reachability for every finding. See
     ``_extract_low_level_sdk`` below.

Plus best-effort **manifest discovery**: an MCP ``server.json`` at the repo
root is parsed for a declared tool list, so a repo that publishes a manifest is
credited even when the handler wiring is opaque to the static pass.

Honesty note: this is name/shape-based discovery, not a resolved import graph.
It is deliberately generous (over-discover rather than miss a tool) to match
the scanner's over-flag philosophy.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass

from . import js_util
from .detectors.base import RepoContext, SourceFile


# --------------------------------------------------------------------- #
# AST decorator helpers (single source of truth; tool_scope_creep imports these)
# --------------------------------------------------------------------- #
def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_tool_decorator(deco: ast.AST) -> bool:
    """True for ``@mcp.tool()`` / ``@server.tool`` / any ``<x>.tool`` shape."""
    target = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted(target)
    return bool(dotted) and dotted.split(".")[-1] == "tool"


def _declared_tool_name(deco: ast.AST, fallback: str) -> str:
    if isinstance(deco, ast.Call):
        for kw in deco.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return fallback


# --------------------------------------------------------------------- #
# Tool registration record
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class ToolRegistration:
    """One discovered MCP tool registration."""

    name: str                 # declared tool name (or handler name fallback)
    handler: str              # handler function name ("" for manifest-only / JS-inline)
    file: str                 # repo-relative posix path of the registration site
    line: int                 # 1-based line of the registration
    source: str               # "py-decorator" | "js-regex" | "manifest"
    node: object | None = None  # the ast.FunctionDef for py-decorator, else None


# JS/TS: `server.tool("name", ...)`  /  `foo.tool('name', ...)` / `.tool(` bare
_JS_TOOL_RE = re.compile(
    r"\b[\w$]+\.tool\s*\(\s*(?:[\"'`]([^\"'`]+)[\"'`])?",
)
# Shared with js_util.JS_SUFFIXES (same set) rather than a private duplicate
# that could silently drift from it.
_JS_SUFFIXES = js_util.JS_SUFFIXES


def _extract_python(f: SourceFile) -> list[ToolRegistration]:
    out: list[ToolRegistration] = []
    if f.tree is None:
        return out
    for node in ast.walk(f.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if _is_tool_decorator(deco):
                out.append(ToolRegistration(
                    name=_declared_tool_name(deco, node.name),
                    handler=node.name,
                    file=f.rel,
                    line=node.lineno,
                    source="py-decorator",
                    node=node,
                ))
                break
    return out


def _extract_js(f: SourceFile) -> list[ToolRegistration]:
    out: list[ToolRegistration] = []
    if f.suffix not in _JS_SUFFIXES:
        return out
    for i, line in enumerate(f.lines, start=1):
        m = _JS_TOOL_RE.search(line)
        if m:
            out.append(ToolRegistration(
                name=m.group(1) or "(inline)",
                handler="",
                file=f.rel,
                line=i,
                source="js-regex",
                node=None,
            ))
    return out


# --------------------------------------------------------------------- #
# Low-level MCP SDK shape (2026-07-23): ``Server()`` + a ``@server.list_tools()``
# handler returning ``types.Tool(...)`` objects, dispatched via a single
# ``@server.call_tool()`` function -- distinct from the FastMCP
# decorator-per-tool shape above (rag-mcp's ``rag_mcp/server.py`` is the
# live in-fleet example; dogfood evidence: this shape returned an EMPTY
# registry before this fix, so ``has_tools`` was False and every finding in
# such a repo graded blanket-UNKNOWN downstream in ``reachability.py``,
# regardless of its true reachability).
#
# Unlike the decorator-per-tool shape, one dispatch function handles every
# registered tool by name -- there is no per-tool handler function to point
# at. The ``@server.call_tool()`` function itself is the call-graph root
# every declared tool shares (same rationale ``reachability.py`` already
# uses tool_nodes for: it's the code that actually runs when any tool is
# invoked).
# --------------------------------------------------------------------- #
def _is_call_tool_decorator(deco: ast.AST) -> bool:
    """True for ``@server.call_tool()`` (low-level MCP SDK dispatch handler)."""
    target = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted(target)
    return bool(dotted) and dotted.split(".")[-1] == "call_tool"


def _is_list_tools_decorator(deco: ast.AST) -> bool:
    """True for ``@server.list_tools()`` (low-level MCP SDK tool-list handler)."""
    target = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted(target)
    return bool(dotted) and dotted.split(".")[-1] == "list_tools"


def _is_tool_construction(call: ast.Call) -> bool:
    """True for ``types.Tool(...)`` / bare ``Tool(...)`` (the low-level SDK's
    tool-metadata constructor -- data, not a decorator)."""
    dotted = _dotted(call.func)
    return bool(dotted) and dotted.split(".")[-1] == "Tool"


def _tool_ctor_name(call: ast.Call) -> str | None:
    """Declared ``name=`` (kwarg, or first positional constant) of a
    ``types.Tool(...)`` / ``Tool(...)`` construction."""
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


def _find_decorated(ctx: RepoContext, is_match) -> list[ast.AST]:
    """Every FunctionDef/AsyncFunctionDef, repo-wide, carrying a decorator
    ``is_match`` accepts."""
    out: list[ast.AST] = []
    for f in ctx.files:
        if f.tree is None:
            continue
        for node in ast.walk(f.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(is_match(d) for d in node.decorator_list):
                out.append(node)
    return out


def _extract_low_level_sdk(ctx: RepoContext) -> list[ToolRegistration]:
    """Low-level MCP SDK pattern: harvest every ``types.Tool(name=...)`` /
    bare ``Tool(name=...)`` construction repo-wide, and correlate it with the
    ``@server.call_tool()`` dispatch function (if any is found anywhere in
    the repo) as its call-graph reachability root.

    Deliberately generous, matching this module's over-discover philosophy:
    a ``Tool(...)`` construction with no resolvable ``name=`` string constant
    still counts (synthetic fallback name) rather than being silently
    dropped, and correlation is repo-wide rather than same-file-only because
    the construction and the dispatch handler commonly live in the same
    file (rag-mcp's shape) but are not required to.
    """
    call_tool_handlers = _find_decorated(ctx, _is_call_tool_decorator)
    if call_tool_handlers:
        # Single-server repos have exactly one dispatch function; the first
        # discovered is the shared root for every declared tool.
        handler_node: ast.AST | None = call_tool_handlers[0]
    else:
        # No call_tool dispatch found -- fall back to the list_tools handler
        # itself as the root so reachability can still say something rather
        # than nothing, on the same generous-over-silent principle.
        list_tools_handlers = _find_decorated(ctx, _is_list_tools_decorator)
        handler_node = list_tools_handlers[0] if list_tools_handlers else None

    out: list[ToolRegistration] = []
    for f in ctx.files:
        if f.tree is None:
            continue
        for node in ast.walk(f.tree):
            if not isinstance(node, ast.Call) or not _is_tool_construction(node):
                continue
            name = _tool_ctor_name(node) or f"(unnamed-tool@{f.rel}:{node.lineno})"
            out.append(ToolRegistration(
                name=name,
                handler=getattr(handler_node, "name", ""),
                file=f.rel,
                line=node.lineno,
                source="py-lowlevel-sdk",
                node=handler_node,
            ))
    return out


def _extract_manifest(ctx: RepoContext) -> list[ToolRegistration]:
    """Parse a root-level MCP ``server.json`` for a declared tool list.

    Best-effort: several manifest shapes exist in the wild. We look for a
    top-level ``tools`` list (or ``mcp.tools`` / ``server.tools``) of objects
    carrying a ``name``. The manifest is read directly (it may not be a scanned
    source suffix), staying within the read-only, static boundary.
    """
    out: list[ToolRegistration] = []
    manifest_path = ctx.root / "server.json"
    if not manifest_path.is_file():
        return out
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return out

    def _tools_list(obj):
        if isinstance(obj, dict):
            for key in ("tools",):
                if isinstance(obj.get(key), list):
                    return obj[key]
            for nest in ("mcp", "server"):
                if isinstance(obj.get(nest), dict) and isinstance(obj[nest].get("tools"), list):
                    return obj[nest]["tools"]
        return None

    tools = _tools_list(data) or []
    for t in tools:
        name = t.get("name") if isinstance(t, dict) else (t if isinstance(t, str) else None)
        if name:
            out.append(ToolRegistration(
                name=str(name),
                handler=str(t.get("handler", "")) if isinstance(t, dict) else "",
                file="server.json",
                line=0,
                source="manifest",
                node=None,
            ))
    return out


def extract_tool_registry(ctx: RepoContext) -> list[ToolRegistration]:
    """All MCP tool registrations discovered in the repo (py + js + manifest)."""
    regs: list[ToolRegistration] = []
    for f in ctx.files:
        regs.extend(_extract_python(f))
        regs.extend(_extract_js(f))
    regs.extend(_extract_low_level_sdk(ctx))
    regs.extend(_extract_manifest(ctx))
    return regs
