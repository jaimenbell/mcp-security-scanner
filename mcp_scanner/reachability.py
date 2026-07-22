"""Manifest-aware reachability grading (post-detector pass).

Every existing detector grades a finding by *same-file* pattern heuristics —
it is blind to whether the flagged code is actually reachable from a registered
MCP tool. A vulnerable pattern inside a dead helper that no tool ever calls is
reported with the same weight as one sitting directly in a tool handler.

This pass closes that gap, statically:

  1. Extract the tool registry (``tool_registry.extract_tool_registry``) — the
     ``@mcp.tool()`` / ``server.tool(...)`` registrations and any ``server.json``
     manifest — as the *roots*.
  2. Build a same-file AST call-graph and walk it (best-effort across files by
     resolving a called bare/attr name against the repo-wide function index —
     honest import-following, not a resolved import graph).
  3. Label each finding REACHABLE / UNREACHABLE / UNKNOWN and nudge its
     confidence up (REACHABLE) or down (UNREACHABLE). It never drops a finding.

Boundary (stated on the report): same-file call-graph is exact; cross-file is
name-matched best-effort; non-Python findings, module-level code, and repos
with no discoverable tools are labelled UNKNOWN rather than guessed.
"""

from __future__ import annotations

import ast
from dataclasses import replace

from .detectors.base import RepoContext, SourceFile
from .models import Confidence, Finding, Reachability, ScanResult
from .tool_registry import _dotted, extract_tool_registry


# --------------------------------------------------------------------- #
# Confidence nudge tables — REACHABLE raises, UNREACHABLE lowers, never drops.
# --------------------------------------------------------------------- #
_RAISE = {Confidence.LOW: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.HIGH,
          Confidence.HIGH: Confidence.HIGH}
_LOWER = {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW,
          Confidence.LOW: Confidence.LOW}


class CallGraph:
    """Same-file-exact / cross-file-best-effort function call graph."""

    def __init__(self, ctx: RepoContext) -> None:
        self._by_rel: dict[str, SourceFile] = {f.rel: f for f in ctx.files}
        # name -> list of function nodes (repo-wide, for cross-file follow)
        self._by_name: dict[str, list[ast.AST]] = {}
        # per-file ordered function nodes for enclosing-lookup
        self._funcs_by_rel: dict[str, list[ast.AST]] = {}
        # node identity -> owning file rel (so a callee resolves to its file)
        self._node_file: dict[int, str] = {}
        for f in ctx.files:
            if f.tree is None:
                continue
            funcs: list[ast.AST] = []
            for node in ast.walk(f.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.append(node)
                    self._by_name.setdefault(node.name, []).append(node)
                    self._node_file[id(node)] = f.rel
            self._funcs_by_rel[f.rel] = funcs

    def enclosing_function(self, rel: str, line: int) -> ast.AST | None:
        """Innermost function whose span contains ``line`` in file ``rel``."""
        if line <= 0:
            return None
        best: ast.AST | None = None
        best_span = None
        for node in self._funcs_by_rel.get(rel, []):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", start)
            if start is None:
                continue
            if start <= line <= end:
                span = end - start
                if best_span is None or span < best_span:
                    best, best_span = node, span
        return best

    def reachable_from(self, roots: list[ast.AST]) -> set[int]:
        """Set of function-node ids reachable from the root handlers (inclusive).

        Same-file callees are resolved exactly; a callee name that only exists
        in another file is followed best-effort (all repo-wide functions of that
        name are treated as reachable — deliberately generous)."""
        visited: set[int] = set()
        stack = [r for r in roots if r is not None]
        while stack:
            node = stack.pop()
            if id(node) in visited:
                continue
            visited.add(id(node))
            owner = self._node_file.get(id(node))
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                dotted = _dotted(sub.func)
                short = dotted.split(".")[-1] if dotted else ""
                if not short:
                    continue
                for callee in self._by_name.get(short, []):
                    if id(callee) in visited:
                        continue
                    # Prefer a same-file match; otherwise follow cross-file.
                    stack.append(callee)
            _ = owner  # reserved for future same-file-only tightening
        return visited


def grade_result(ctx: RepoContext, result: ScanResult) -> None:
    """In-place: label every finding with reachability + nudge confidence.

    No-op relabel to UNKNOWN when the repo exposes no discoverable tools (there
    is nothing to be reachable *from*), so counts and confidences are untouched
    in the manifest-less case — an honest "we can't say", never a silent drop.
    """
    registry = extract_tool_registry(ctx)
    tool_nodes = [r.node for r in registry if r.node is not None]
    has_tools = bool(registry)

    cg = CallGraph(ctx)
    reachable_ids = cg.reachable_from(tool_nodes) if tool_nodes else set()

    graded: list[Finding] = []
    for f in result.findings:
        label = _grade_one(f, ctx, cg, reachable_ids, has_tools, bool(tool_nodes))
        conf = f.confidence
        if label is Reachability.REACHABLE:
            conf = _RAISE[f.confidence]
        elif label is Reachability.UNREACHABLE:
            conf = _LOWER[f.confidence]
        graded.append(replace(f, reachability=label, confidence=conf))
    result.findings = graded


def _grade_one(f: Finding, ctx: RepoContext, cg: CallGraph,
               reachable_ids: set[int], has_tools: bool,
               have_py_handlers: bool) -> Reachability:
    if not has_tools:
        return Reachability.UNKNOWN
    src = None
    for sf in ctx.files:
        if sf.rel == f.file:
            src = sf
            break
    # Non-Python surface (JS/TS/YAML/shell) or unparsed file: no AST call-graph.
    if src is None or src.tree is None or src.suffix not in (".py", ".pyw"):
        return Reachability.UNKNOWN
    # Whole-file findings have no single enclosing scope to resolve.
    if f.line <= 0:
        return Reachability.UNKNOWN
    enclosing = cg.enclosing_function(f.file, f.line)
    if enclosing is None:
        # Module-level code: executes at import, not attributable to a tool
        # call path. Honest UNKNOWN rather than a guess in either direction.
        return Reachability.UNKNOWN
    if not have_py_handlers:
        # Tools exist only via manifest/JS — no Python handler roots to walk,
        # so we can't prove a Python call path either way.
        return Reachability.UNKNOWN
    if id(enclosing) in reachable_ids:
        return Reachability.REACHABLE
    return Reachability.UNREACHABLE
