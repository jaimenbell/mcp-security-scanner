"""Shared MCP tool-registry extraction.

A single source of truth for "which functions in this repo are registered as
MCP tools", used by two consumers:

  * ``detectors/tool_scope_creep.py`` — was carrying its own private copies of
    the decorator-shape helpers; they now live here so there is one parser, not
    two that can drift.
  * ``reachability.py`` — needs the registered tool handlers as the roots of
    its call-graph reachability grading.

Discovery covers the two dominant real-world shapes in this fleet:

  1. **Python FastMCP decorators** — ``@mcp.tool()`` / ``@server.tool()`` (and
     any ``<x>.tool`` attribute call/name), parsed from the AST.
  2. **JS/TS registrations** — ``server.tool("name", ...)`` /
     ``<x>.tool(...)`` calls, matched at regex level (the JS surface has no AST
     path in this scanner, stated honestly on every report).

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
_JS_SUFFIXES = {".js", ".mjs", ".ts"}


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
    regs.extend(_extract_manifest(ctx))
    return regs
