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

2026-07-23 N-vote correction: the first cut of the low-level-SDK discovery
(3, above) rooted EVERY ``Tool()`` construction repo-wide to whichever
``@server.call_tool()`` handler a nondeterministic file walk happened to
find first. In any repo with more than one low-level dispatcher (a vendored
SDK example next to the real server, an admin/public split, a monorepo), a
genuinely tool-reachable sink could be silently rooted to the WRONG
dispatcher and mis-graded CLI_ONLY/UNCALLED with lowered confidence instead
of the honest pre-patch UNKNOWN -- a confident severity downgrade, the one
direction this scanner must never fail in. Fixed by scoping the Tool()<->
dispatcher correlation to a single file/module (never repo-wide) and never
guessing a root when a file's dispatcher is ambiguous (zero or more than one
candidate) -- see ``_extract_low_level_sdk``. A same-named non-MCP ``Tool``/
``call_tool`` (e.g. a LangChain-shaped local class) is excluded via an
import-provenance gate (``_file_imports_mcp``): a file must actually import
something from the ``mcp`` package before its Server()/list_tools/call_tool/
Tool() shapes are trusted.

Known gap, disclosed rather than silently left (out of scope for this pass):
``detectors/tool_scope_creep.py`` only consumes this registry's JS-regex
entries (``source == "js-regex"``) -- its Python path re-derives decorator
matches directly via ``_is_tool_decorator`` rather than reading
``py-decorator``/``py-lowlevel-sdk`` registrations. A repo using ONLY the
low-level SDK shape therefore gets zero write-tools-on-by-default /
tool-scope-creep (detector 5) coverage today. Wiring that is a separate,
future increment.
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
# at. The ``@server.call_tool()`` function is the call-graph root a file's
# declared tools share -- but see the per-file scoping note on
# ``_extract_low_level_sdk`` below (2026-07-23 N-vote correction): that
# correlation is same-file only, never a repo-wide first-found guess.
# --------------------------------------------------------------------- #
def _is_call_tool_decorator(deco: ast.AST) -> bool:
    """True for ``@server.call_tool()`` (low-level MCP SDK dispatch handler)."""
    target = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted(target)
    return bool(dotted) and dotted.split(".")[-1] == "call_tool"


def _is_tool_construction(call: ast.Call) -> bool:
    """True for ``types.Tool(...)`` / bare ``Tool(...)`` (the low-level SDK's
    tool-metadata constructor -- data, not a decorator). Callers must ALSO
    gate on ``_file_imports_mcp`` for the owning file -- this predicate is
    name-shape-only and, alone, matches an unrelated same-named class (e.g.
    LangChain's ``Tool``)."""
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


def _file_imports_mcp(f: SourceFile) -> bool:
    """Import-provenance gate (2026-07-23 N-vote fix, P1): True only if this
    file actually imports something from the ``mcp`` package (``import mcp``
    / ``import mcp.xxx`` / ``from mcp import ...`` / ``from mcp.xxx import
    ...``). Required before a file's ``Server()``/``call_tool()``/
    ``list_tools()``/``Tool()`` name-shapes are trusted as the real MCP
    low-level SDK -- otherwise a same-named non-MCP class (a LangChain
    ``class Tool``, an unrelated ``.call_tool()``-named method on some other
    framework's dispatcher) flips ``has_tools`` True and can claim a bogus
    reachability root for a sink the real server never exposes (reproduced
    by the N-vote refuters)."""
    if f.tree is None:
        return False
    for node in ast.walk(f.tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "mcp" or alias.name.startswith("mcp.") for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "mcp" or node.module.startswith("mcp.")):
                return True
    return False


def _decorated_in_file(f: SourceFile, is_match) -> list[ast.AST]:
    """Every FunctionDef/AsyncFunctionDef in this ONE file carrying a
    decorator ``is_match`` accepts. Same-file only by design -- see
    ``_extract_low_level_sdk``."""
    if f.tree is None:
        return []
    return [
        n for n in ast.walk(f.tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(is_match(d) for d in n.decorator_list)
    ]


def _extract_low_level_sdk(ctx: RepoContext) -> list[ToolRegistration]:
    """Low-level MCP SDK pattern: harvest every ``types.Tool(name=...)`` /
    bare ``Tool(name=...)`` construction, gated per file on
    ``_file_imports_mcp``, and correlate it with a call-graph reachability
    root -- SAME-FILE ONLY.

    2026-07-23 N-vote correction (round 2): the original cut rooted every
    Tool() construction repo-wide to whichever ``@server.call_tool()``
    handler a nondeterministic file walk found first -- wrong, and sometimes
    a confident severity DOWNGRADE, in any repo with more than one low-level
    dispatcher. Correlation was scoped to the file the Tool() construction
    lives in: exactly one ``@server.call_tool()`` handler in that file is
    the root; anything else (zero, or more than one) claims no root.

    2026-07-23 round 3 (Opus final-verify BLOCKED finding): round 2 still
    fell back to a same-file ``@server.list_tools()`` handler as the root
    when zero ``call_tool`` handlers were found -- semantically wrong.
    ``list_tools`` returns tool METADATA; it never executes tool logic, so
    rooting a call-graph walk there is not "the honest UNKNOWN behavior," it
    MANUFACTURES a bogus root -- reproduced on the common split-module shape
    (a declaration module with ``Tool(...)`` + ``@server.list_tools()`` and
    no ``call_tool``, dispatch living in a separate module) where it
    confidently downgraded a genuinely tool-reachable sink to CLI_ONLY.
    That fallback is REMOVED: zero ``call_tool`` handlers in a file ->
    ``handler_node=None``, full stop. ``node=None`` on a ``py-lowlevel-sdk``
    registration is now also a signal ``reachability.py``/``taint.py`` check
    explicitly (``unrooted_lowlevel`` / the reachable_ids gate) so a finding
    elsewhere in the SAME repo that has a valid root can't cause a
    node=None tool's own findings to be confidently mis-graded either --
    see ``reachability.grade_result``.

    Iteration is over ``sorted(ctx.files, key=rel)`` so output order (and
    which same-file handler is picked when, rarely, more than one exists) is
    deterministic regardless of the underlying file-discovery order.
    """
    out: list[ToolRegistration] = []
    for f in sorted(ctx.files, key=lambda sf: sf.rel):
        if f.tree is None or not _file_imports_mcp(f):
            continue

        call_tool_handlers = _decorated_in_file(f, _is_call_tool_decorator)
        if len(call_tool_handlers) == 1:
            handler_node: ast.AST | None = call_tool_handlers[0]
        else:
            # Zero call_tool handlers (round-3: no list_tools fallback --
            # list_tools never executes tool logic, so it is not a valid
            # call-graph root) or more than one candidate in this single
            # file (genuinely ambiguous) -- never guess.
            handler_node = None

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
