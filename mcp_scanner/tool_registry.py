"""Shared MCP tool-registry extraction.

A single source of truth for "which functions in this repo are registered as
MCP tools", used by two consumers:

  * ``detectors/tool_scope_creep.py`` — was carrying its own private copies of
    the decorator-shape helpers; they now live here so there is one parser, not
    two that can drift.
  * ``reachability.py`` — needs the registered tool handlers as the roots of
    its call-graph reachability grading.

Discovery covers these real-world shapes:

  1. **Python FastMCP decorators** — ``@mcp.tool()`` / ``@server.tool()`` (and
     any ``<x>.tool`` attribute call/name), parsed from the AST.
  2. **JS/TS registrations** — four idioms, matched at regex level (the JS
     surface has no AST path in this scanner, stated honestly on every
     report): the deprecated ``server.tool("name", ...)``, the current SDK's
     ``server.registerTool(name, config, handler)``, fastmcp's
     ``server.addTool({ name, ... })``, and the low-level TS SDK's
     ``setRequestHandler(CallToolRequestSchema, ...)`` dispatcher. See
     ``_extract_js``; ``node`` is ``None`` on every one of them, without
     exception.
  2b. **Python FastMCP by CALL** (2026-07-30) — ``self.tool(handler,
     name=...)``, how a ``FastMCP`` subclass that builds handlers
     programmatically registers them. See ``_extract_python_calls``.
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

2026-07-23 (later same day): the gap above -- ``detectors/tool_scope_creep.py``
and ``detectors/secret_leak_response.py`` only understood decorator-style
registration, so a repo using ONLY the low-level SDK shape got zero
write-tools-on-by-default / tool-scope-creep (detector 5) and zero
secret-leak-via-tool-response (detector 6) coverage -- is now closed. Both
detectors treat a provenance-gated (``_file_imports_mcp``) ``@server.call_tool()``
handler as an inspection root via ``dispatch_segments`` (below): each
top-level ``if <x> == "name": ... elif <x> == "other": ...`` branch in the
handler is an unambiguous per-tool effective body; anything not attributable
to one specific literal tool name (an ``in (...)`` / other comparison, the
final ``else``, or code outside the if/elif chain entirely) is inspected too
but attributed to the dispatch handler itself, never guessed at one tool --
same never-guess-a-root philosophy as ``_extract_low_level_sdk``. Known
boundary, disclosed rather than silently left: this is a literal-equality
if/elif walk, not real dataflow -- a dict-keyed dispatch table
(``_HANDLERS[name](arguments)``), a match/case statement, or a name check
via a helper function/lookup table is not recognized as attributable dispatch
and falls back to whole-handler attribution (honest UNKNOWN-style fallback,
never a wrong per-tool guess).
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


# --------------------------------------------------------------------- #
# JS/TS registration idioms (2026-07-30 recall slice 1)
#
# The five-target hand audit pinned in ``ecoscan-targets.lock.json`` found the
# original single pattern below -- ``<x>.tool(`` -- matched the DEPRECATED
# ``server.tool()`` API and nothing else, so four of five real MCP servers
# registered zero tools and the fifth registered one unnamed placeholder.
# ``has_tools`` was False, which cascades: ``grading._reason_for`` reports "no
# MCP tool registrations were found", and ``tool_scope_creep._scan_js`` /
# ``secret_leak_response._scan_js`` -- both keyed on ``source == "js-regex"``
# -- never inspected a single handler window.
#
# Every pattern here stays ``source="js-regex"`` (so both JS window detectors
# pick it up with no change) and ``node=None`` (see ``_extract_js``).
# --------------------------------------------------------------------- #

# Deprecated MCP TS SDK: `server.tool("name", ...)` / `foo.tool('name', ...)`
_JS_TOOL_RE = re.compile(
    r"\b[\w$]+\.tool\s*\(\s*(?:[\"'`]([^\"'`]+)[\"'`])?",
)
# Current MCP TS SDK: `server.registerTool(name, config, handler)`
# (airtable-mcp-server -- 16 call sites, name usually on the NEXT line).
_JS_REGISTER_TOOL_RE = re.compile(
    r"\b[\w$]+\.registerTool\s*\(\s*(?:[\"'`]([^\"'`]+)[\"'`])?",
)
# fastmcp TS SDK: `server.addTool({ name: '...', ... })` (firecrawl-mcp-server).
# The `{` is required so the four non-registration shapes firecrawl's own
# source carries -- `Pick<FastMCP<S>, 'addTool'>`, `Parameters<typeof
# server.addTool>`, `server.addTool.bind(server)`, and `addTool: (...)` as an
# object property -- cannot match.
_JS_ADD_TOOL_RE = re.compile(r"\b[\w$]+\.addTool\s*\(\s*\{")
# Low-level TS SDK: `setRequestHandler(CallToolRequestSchema, handler)`
# (notion-mcp-server).  ``ListToolsRequestSchema`` is deliberately NOT matched:
# it returns tool METADATA and never executes tool logic, the same distinction
# ``_extract_low_level_sdk`` enforces on the Python side (2026-07-23 round-3
# N-vote fix).  Anchoring a detector window on the tool-listing code would scan
# it as though it were a handler body.
_JS_CALLTOOL_DISPATCH_RE = re.compile(
    r"\.setRequestHandler\s*\(\s*CallToolRequestSchema\b",
)

# Name recovery for the two multi-line shapes above.
# `registerTool(` + a following line that is JUST a string literal + comma.
_JS_LEADING_STRING_RE = re.compile(r"^\s*[\"'`]([^\"'`]+)[\"'`]\s*(?:,|$)")
# `addTool({` + a `name: '...'` property within a short window.
_JS_NAME_PROP_RE = re.compile(r"(?:^|[{,\s])name\s*:\s*[\"'`]([^\"'`]+)[\"'`]")
# Lines of look-ahead allowed when recovering a name.  Deliberately small: a
# wide window would start capturing an unrelated nested `name:` and label a
# tool with something that is not its name.
_JS_NAME_LOOKAHEAD = 4

# Shared with js_util.JS_SUFFIXES (same set) rather than a private duplicate
# that could silently drift from it.
_JS_SUFFIXES = js_util.JS_SUFFIXES

# Python registration sources whose ``node`` may legitimately be ``None``
# (a real tool exists, but no unambiguous call-graph root could be attributed
# to it without guessing).  ``reachability.grade_result`` must withhold its
# CLI_ONLY/UNCALLED downgrade repo-wide when any of these is present --
# soundness over decidability.  Imported by ``reachability`` rather than
# copied, so the two cannot drift.
UNROOTED_PY_SOURCES = ("py-lowlevel-sdk", "py-call")

# Top-level packages whose import counts as MCP provenance for the FastMCP
# CALL-registration shape (``self.tool(handler, name=...)``).  Two distinct
# distributions expose ``FastMCP``: ``mcp.server.fastmcp`` (bundled with the
# official SDK) and the standalone ``fastmcp`` package -- mcp-server-qdrant
# imports the latter, so an ``mcp``-only gate found zero of its 2 tools.
_FASTMCP_IMPORT_ROOTS = ("mcp", "fastmcp")


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


def _js_next_code_line(lines: list[str], idx: int) -> str | None:
    """The next non-blank, non-comment line after 0-based ``idx``, or None."""
    for j in range(idx + 1, min(idx + 1 + _JS_NAME_LOOKAHEAD, len(lines))):
        raw = lines[j]
        if not raw.strip() or js_util.is_comment_line(raw):
            continue
        return js_util.code_part(raw)
    return None


def _js_name_in_window(lines: list[str], idx: int, tail: str) -> str | None:
    """First ``name: "..."`` property in ``tail`` (rest of the matched line)
    or the next few code lines -- the fastmcp ``addTool({ name: ... })``
    shape.  Window-limited on purpose: see ``_JS_NAME_LOOKAHEAD``."""
    m = _JS_NAME_PROP_RE.search(tail)
    if m:
        return m.group(1)
    for j in range(idx + 1, min(idx + 1 + _JS_NAME_LOOKAHEAD, len(lines))):
        raw = lines[j]
        if not raw.strip() or js_util.is_comment_line(raw):
            continue
        m = _JS_NAME_PROP_RE.search(js_util.code_part(raw))
        if m:
            return m.group(1)
    return None


def _extract_js(f: SourceFile) -> list[ToolRegistration]:
    """Regex-level JS/TS tool discovery -- four registration idioms.

    ``node`` is ``None`` on every record this function produces, without
    exception.  ``ToolRegistration.node`` is consumed as an ``ast.AST`` by
    ``reachability.reachable_from`` and ``taint.propagate``; a regex match has
    no AST node, and inventing one would feed a non-AST object into the Python
    call-graph.  This function buys ``has_tools`` and the JS window detectors'
    inspection windows.  It does NOT give JS/TS a call graph.
    """
    out: list[ToolRegistration] = []
    if f.suffix not in _JS_SUFFIXES:
        return out
    lines = f.lines
    for idx, raw in enumerate(lines):
        if js_util.is_comment_line(raw):
            continue
        line = js_util.code_part(raw)
        lineno = idx + 1

        # Deprecated `.tool("name", ...)` -- unchanged behaviour.
        m = _JS_TOOL_RE.search(line)
        if m:
            out.append(ToolRegistration(
                name=m.group(1) or "(inline)", handler="", file=f.rel,
                line=lineno, source="js-regex", node=None,
            ))
            continue

        # Current SDK `.registerTool(name, config, handler)`.  When the name
        # is not on the call line it is the very NEXT code line and nothing
        # else -- only that one line is inspected, so a variable first
        # argument (`registerTool(toolName, ...)`) yields "(inline)" rather
        # than a string lifted out of the config object.
        m = _JS_REGISTER_TOOL_RE.search(line)
        if m:
            name = m.group(1)
            if not name:
                nxt = _js_next_code_line(lines, idx)
                if nxt is not None:
                    lead = _JS_LEADING_STRING_RE.match(nxt)
                    if lead:
                        name = lead.group(1)
            out.append(ToolRegistration(
                name=name or "(inline)", handler="", file=f.rel,
                line=lineno, source="js-regex", node=None,
            ))
            continue

        # fastmcp `.addTool({ name: "...", ... })`.
        m = _JS_ADD_TOOL_RE.search(line)
        if m:
            name = _js_name_in_window(lines, idx, line[m.end():])
            out.append(ToolRegistration(
                name=name or "(inline)", handler="", file=f.rel,
                line=lineno, source="js-regex", node=None,
            ))
            continue

        # Low-level SDK `setRequestHandler(CallToolRequestSchema, ...)`.  One
        # dispatcher serves every tool and the names are resolved at runtime
        # (notion generates them from an OpenAPI spec), so there is no static
        # name to recover -- "(inline)" is the honest label, and the detector
        # windows anchor on the dispatcher body, which is what executes.
        if _JS_CALLTOOL_DISPATCH_RE.search(line):
            out.append(ToolRegistration(
                name="(inline)", handler="", file=f.rel,
                line=lineno, source="js-regex", node=None,
            ))
    return out


def _extract_python_calls(f: SourceFile) -> list[ToolRegistration]:
    """Python FastMCP registration by CALL rather than decorator:
    ``self.tool(handler, name="...")`` (2026-07-30 recall slice 1).

    ``FastMCP.tool`` is a normal method, and a subclass that builds its
    handlers programmatically calls it directly instead of decorating.
    mcp-server-qdrant does exactly this (``mcp_server.py:187,195``) and
    registered 0 of its 2 tools before this path existed -- the only Python
    target in the pinned set, and it was reporting ``has_tools=False``.

    Two guards, both deliberate:

    * **Provenance.** Gated on an import from ``mcp`` OR ``fastmcp``,
      mirroring ``_extract_low_level_sdk``'s ``_file_imports_mcp``.  Plenty of
      non-MCP libraries have a ``.tool(...)`` method, and a bogus registration
      flips ``has_tools`` for a repo that exposes no MCP tools at all.
      ``fastmcp`` is in the allowed set because the standalone package is a
      distinct distribution from ``mcp.server.fastmcp`` and qdrant imports the
      standalone one (``from fastmcp import Context, FastMCP``) -- gating on
      ``mcp`` alone found zero tools in the one Python target in the pinned
      set.  ``_extract_low_level_sdk`` keeps the narrower ``mcp``-only gate:
      ``Server``/``call_tool``/``types.Tool`` are low-level ``mcp`` SDK
      symbols and ``fastmcp`` provenance would not justify trusting them.
    * **Never guess a root.** ``node`` is set only when the first positional
      argument is the name of a function defined exactly once in this same
      file -- an unambiguous, genuine ``FunctionDef``.  qdrant's real argument
      is a local alias (``find_foo = find``) that is conditionally REASSIGNED
      to a wrapper, so resolving it would be a guess; a wrong root is a
      confident mis-grade, the failure ``_extract_low_level_sdk`` was
      corrected for twice.  Unrooted records are declared via
      ``UNROOTED_PY_SOURCES`` so ``reachability`` withholds its downgrade
      repo-wide.
    """
    out: list[ToolRegistration] = []
    if f.tree is None or not _file_imports_mcp(f, roots=_FASTMCP_IMPORT_ROOTS):
        return out

    decorator_call_ids: set[int] = set()
    func_name_counts: dict[str, int] = {}
    funcdefs: dict[str, ast.AST] = {}
    for node in ast.walk(f.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name_counts[node.name] = func_name_counts.get(node.name, 0) + 1
            funcdefs.setdefault(node.name, node)
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call):
                    decorator_call_ids.add(id(deco))

    for node in ast.walk(f.tree):
        if not isinstance(node, ast.Call) or id(node) in decorator_call_ids:
            continue
        dotted = _dotted(node.func)
        if not dotted or dotted.split(".")[-1] != "tool":
            continue
        if not node.args:
            # `mcp.tool()` with no positional argument is the decorator
            # FACTORY form; the decorator path above already owns it.
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant):
            # `mcp.tool("name")` registers no handler here -- it is the
            # decorator factory again, or something else entirely.
            continue
        handler_name = first.id if isinstance(first, ast.Name) else ""
        handler_node: ast.AST | None = None
        if handler_name and func_name_counts.get(handler_name) == 1:
            handler_node = funcdefs.get(handler_name)
        fallback = handler_name or f"(unnamed-tool@{f.rel}:{node.lineno})"
        out.append(ToolRegistration(
            name=_declared_tool_name(node, fallback),
            handler=handler_name,
            file=f.rel,
            line=node.lineno,
            source="py-call",
            node=handler_node,
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


def _file_imports_mcp(f: SourceFile, roots: tuple[str, ...] = ("mcp",)) -> bool:
    """Import-provenance gate (2026-07-23 N-vote fix, P1): True only if this
    file actually imports something from one of ``roots`` (``import mcp``
    / ``import mcp.xxx`` / ``from mcp import ...`` / ``from mcp.xxx import
    ...``). ``roots`` defaults to the low-level SDK's ``mcp`` package only;
    ``_extract_python_calls`` widens it to ``_FASTMCP_IMPORT_ROOTS`` because
    the standalone ``fastmcp`` distribution is a separate top-level package.
    Required before a file's ``Server()``/``call_tool()``/
    ``list_tools()``/``Tool()`` name-shapes are trusted as the real MCP
    low-level SDK -- otherwise a same-named non-MCP class (a LangChain
    ``class Tool``, an unrelated ``.call_tool()``-named method on some other
    framework's dispatcher) flips ``has_tools`` True and can claim a bogus
    reachability root for a sink the real server never exposes (reproduced
    by the N-vote refuters)."""
    if f.tree is None:
        return False

    def _is_root(mod: str) -> bool:
        return any(mod == r or mod.startswith(r + ".") for r in roots)

    for node in ast.walk(f.tree):
        if isinstance(node, ast.Import):
            if any(_is_root(alias.name) for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and _is_root(node.module):
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


# --------------------------------------------------------------------- #
# Dispatch-branch attribution (2026-07-23): shared by
# ``detectors/tool_scope_creep.py`` and ``detectors/secret_leak_response.py``
# so each has ONE parser for "what is a low-level SDK ``call_tool`` handler's
# per-tool effective body", not two that can drift.
# --------------------------------------------------------------------- #
def _string_eq_literal(test: ast.AST) -> str | None:
    """If ``test`` is ``<expr> == "literal"`` (either operand order) with
    exactly one comparison operator, return the literal string --
    otherwise ``None``. Only this exact shape counts as an unambiguous
    tool-name dispatch discriminant; an ``in (...)`` membership test, a
    chained comparison, or a non-``Eq`` operator is ambiguous and must not
    be guessed at (mirrors this module's never-guess-a-root philosophy)."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return None
    left, right = test.left, test.comparators[0]
    if isinstance(right, ast.Constant) and isinstance(right.value, str):
        return right.value
    if isinstance(left, ast.Constant) and isinstance(left.value, str):
        return left.value
    return None


def _eq_discriminant(test: ast.AST) -> ast.AST | None:
    """The non-literal side of an ``<expr> == "literal"`` compare (either
    operand order) -- the expression a dispatch chain is actually
    discriminating on. ``None`` if ``test`` isn't that exact shape (mirrors
    ``_string_eq_literal``'s gate, just returning the other side)."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return None
    left, right = test.left, test.comparators[0]
    if isinstance(right, ast.Constant) and isinstance(right.value, str):
        return left
    if isinstance(left, ast.Constant) and isinstance(left.value, str):
        return right
    return None


def _first_param_name(handler: ast.AST) -> str | None:
    """The handler's first non-``self``/``cls`` positional parameter name
    (``name`` in ``async def call_tool(name, arguments)``) -- the
    conventional MCP low-level SDK dispatch discriminant, used to pick the
    RIGHT if/elif chain when a handler has more than one top-level
    string-equality ``if`` (2026-07-23 P1 N-vote fix, refuter A's P3: the
    previous first-if-found walk could root on an unrelated earlier ``if``
    that happened to compare some other variable to a string literal)."""
    args = getattr(handler, "args", None)
    if args is None:
        return None
    for a in list(getattr(args, "posonlyargs", [])) + list(args.args):
        if a.arg in ("self", "cls"):
            continue
        return a.arg
    return None


def _find_dispatch_chain(handler: ast.AST) -> tuple[int | None, ast.If | None, str | None]:
    """Locate the handler's dispatch if/elif chain: ``(index_in_body,
    if_node, discriminant_dump)`` or ``(None, None, None)`` if no top-level
    ``if <x> == "literal":`` exists at all.

    Among every top-level ``if`` whose test is a plain string-equality
    compare, prefer the one whose discriminant is the handler's first
    parameter (the conventional ``call_tool(name, arguments)`` shape); if
    none matches, fall back to the first such ``if`` found (previous
    behavior, still disclosed as a heuristic, not proof)."""
    body = list(getattr(handler, "body", None) or [])
    candidates: list[tuple[int, ast.If, ast.AST]] = []
    for i, stmt in enumerate(body):
        if isinstance(stmt, ast.If):
            disc = _eq_discriminant(stmt.test)
            if disc is not None:
                candidates.append((i, stmt, disc))
    if not candidates:
        return None, None, None

    first_param = _first_param_name(handler)
    if first_param:
        for i, stmt, disc in candidates:
            if isinstance(disc, ast.Name) and disc.id == first_param:
                return i, stmt, ast.dump(disc)

    i, stmt, disc = candidates[0]
    return i, stmt, ast.dump(disc)


def dispatch_segments(handler: ast.AST) -> list[tuple[str | None, list[ast.stmt], bool]]:
    """Split a low-level SDK ``call_tool`` handler's body into
    ``(tool_name, stmts, shared)`` segments -- the per-tool "effective body"
    that ``tool_scope_creep.py`` (mutating-sink/gate inspection) and
    ``secret_leak_response.py`` (leak-shaped-return inspection) each need,
    without either re-deriving its own dispatch-branch walk.

    ``tool_name`` is the literal from an unambiguous ``if <x> == "name":`` /
    ``elif <x> == "name":`` link in the handler's dispatch chain, found via
    ``_find_dispatch_chain``. Every link in the chain must compare the exact
    SAME discriminant expression (structural equality via ``ast.dump``) --
    2026-07-23 P1 N-vote fix: the previous walk accepted ANY string-equality
    test at each link regardless of what it compared, so
    ``if name == "safe_tool": ... elif arguments.get("mode") ==
    "delete_everything": os.remove(...)`` fabricated a root for a tool named
    ``'delete_everything'`` that was never registered. Once one link's
    discriminant mismatches, that link AND every link after it in the chain
    tag ``None`` (chain integrity broken, never partially trusted).

    ``tool_name`` is ``None`` for a segment that cannot be attributed to one
    specific tool -- a final ``else``, a branch whose test isn't a plain
    string-equality compare (``in (...)``, multiple names, ...), a
    discriminant-mismatched link (see above), or code outside the if/elif
    chain entirely. Consumers must attribute ``None`` segments to the
    dispatch handler itself, never guess a specific tool -- same
    never-guess-a-root philosophy as ``_extract_low_level_sdk``.

    ``shared`` is ``True`` only for the segment of statements BEFORE the
    dispatch chain in the handler's top-level body (a shared pre-dispatch
    auth/validation check that runs unconditionally for every branch, e.g.
    ``if not check_permission(name): raise ...`` above the if/elif) --
    2026-07-23 P0-1 N-vote fix companion: callers need this to know which
    ``None`` segments legitimately gate every OTHER segment too, versus an
    ambiguous/final-else branch or trailing code, which must gate only
    itself. Every branch segment and any trailing (post-chain) leftover are
    ``shared=False``.

    When the handler's top level has no such if/elif dispatch shape at all
    (a dict-keyed dispatch table, a ``match``/``case`` statement, or any
    other shape this walk doesn't recognize), the single segment
    ``(None, handler.body, False)`` is returned -- the honest whole-handler
    fallback, disclosed rather than a wrong per-tool guess.
    """
    body = list(getattr(handler, "body", None) or [])
    idx, dispatch_if, discriminant_dump = _find_dispatch_chain(handler)
    if dispatch_if is None:
        return [(None, body, False)]

    chain_segments: list[tuple[str | None, list[ast.stmt], bool]] = []
    cur: ast.If = dispatch_if
    chain_broken = False
    while True:
        disc = _eq_discriminant(cur.test)
        lit = _string_eq_literal(cur.test)
        if not chain_broken and disc is not None and ast.dump(disc) == discriminant_dump:
            name = lit
        else:
            name = None
            chain_broken = True
        chain_segments.append((name, cur.body, False))
        if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
            cur = cur.orelse[0]
            continue
        if cur.orelse:
            chain_segments.append((None, cur.orelse, False))
        break

    result: list[tuple[str | None, list[ast.stmt], bool]] = []
    pre = body[:idx]
    if pre:
        result.append((None, pre, True))
    result.extend(chain_segments)
    post = body[idx + 1:]
    if post:
        result.append((None, post, False))
    return result


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
        regs.extend(_extract_python_calls(f))
        regs.extend(_extract_js(f))
    regs.extend(_extract_low_level_sdk(ctx))
    regs.extend(_extract_manifest(ctx))
    return regs
