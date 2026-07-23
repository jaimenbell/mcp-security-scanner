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
  3. Label each finding REACHABLE / CLI_ONLY / UNCALLED / UNKNOWN and nudge
     its confidence up (REACHABLE) or down (CLI_ONLY, UNCALLED). It never
     drops a finding.

Boundary (stated on the report): same-file call-graph is exact; cross-file is
name-matched best-effort; non-Python findings, module-level code, and repos
with no discoverable tools are labelled UNKNOWN rather than guessed.

CLI_ONLY / UNCALLED (2026-07-22, dogfood finding on rag-mcp's
``lock.py:144``): when a finding is NOT reachable from any tool root, a
reverse name-matched caller search decides whether that's because (a) the
sink has a real caller elsewhere that just never traces back to a tool
(CLI_ONLY -- typically an argv/CLI-main entrypoint or a test file; the
caller-chain is attached as evidence) or (b) nothing calls it at all
(UNCALLED). Both are withheld in favor of UNKNOWN whenever the repo contains
any statically-unresolvable call site (``getattr(...)(...)``, dict/subscript
dispatch, etc.) — such a call could reach the finding by a path this pass
cannot see, so asserting CLI_ONLY/UNCALLED there would overclaim
decidability. UNREACHABLE stays in the enum for schema stability but the
Python-AST-decidable branch no longer emits it.
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
        # short callee name -> every (file, lineno) Call site in the repo,
        # module-level AND function-level. Reverse index for the CLI_ONLY /
        # UNCALLED decidability pass (2026-07-22) -- who calls a given
        # function, from anywhere, not just from a tool root.
        self._call_sites_by_name: dict[str, list[tuple[str, int]]] = {}
        # True if the repo contains any statically-unresolvable call target
        # (``getattr(x, name)(...)``, ``obj[key](...)``, etc.) -- such a call
        # could reach ANY function at runtime, so CLI_ONLY/UNCALLED must not
        # be asserted anywhere in a repo that has one (soundness over
        # decidability; see Reachability.UNKNOWN).
        self.dynamic_dispatch_present: bool = False
        for f in ctx.files:
            if f.tree is None:
                continue
            funcs: list[ast.AST] = []
            for node in ast.walk(f.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.append(node)
                    self._by_name.setdefault(node.name, []).append(node)
                    self._node_file[id(node)] = f.rel
                elif isinstance(node, ast.Call):
                    dotted = _dotted(node.func)
                    short = dotted.split(".")[-1] if dotted else ""
                    if not short:
                        # Call target itself unresolvable, e.g.
                        # ``getattr(obj, name)(args)`` or ``d[key](args)``.
                        self.dynamic_dispatch_present = True
                        continue
                    if short == "getattr" and len(node.args) >= 2 and not isinstance(
                        node.args[1], ast.Constant
                    ):
                        # ``getattr(obj, name)`` with a NON-literal attribute
                        # name -- the resolved attribute (and any function it
                        # names) is only known at runtime, even if the result
                        # is invoked later via a plain local-variable call
                        # this pass would otherwise treat as fully resolved.
                        self.dynamic_dispatch_present = True
                    elif short in ("locals", "globals", "vars"):
                        # Name-by-string dispatch via the local/global
                        # namespace, e.g. ``globals()[name](args)``.
                        self.dynamic_dispatch_present = True
                    self._call_sites_by_name.setdefault(short, []).append(
                        (f.rel, node.lineno)
                    )
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

    def callers_outside(self, enclosing: ast.AST) -> list[tuple[str, int]]:
        """Every repo-wide call site that invokes ``enclosing`` by name,
        excluding call sites lexically inside ``enclosing``'s own body (a
        recursive self-call is not an external caller). Best-effort
        name-matched, same fidelity as ``reachable_from``'s forward walk --
        if a call site with this name exists ANYWHERE outside ``enclosing``,
        forward-walk already failed to reach ``enclosing`` from a tool root
        (that's why this method is only consulted for non-reachable
        findings), so any caller found here is guaranteed non-tool-descended
        at this same resolution fidelity."""
        name = getattr(enclosing, "name", None)
        if not name:
            return []
        owner = self._node_file.get(id(enclosing))
        start = getattr(enclosing, "lineno", None)
        end = getattr(enclosing, "end_lineno", start)
        out: list[tuple[str, int]] = []
        for file_rel, lineno in self._call_sites_by_name.get(name, []):
            if file_rel == owner and start is not None and start <= lineno <= end:
                continue
            out.append((file_rel, lineno))
        return out

    def caller_chain(self, enclosing: ast.AST, max_depth: int = 5) -> list[str]:
        """Best-effort single-path caller chain from ``enclosing`` outward,
        for finding-output evidence. Walks the FIRST caller found at each
        hop (deliberately simple -- this is evidence for a human triager,
        not an exhaustive proof), stopping at a module-level call site (the
        likely argv/CLI-main root), a cycle, or ``max_depth``."""
        chain: list[str] = []
        current = enclosing
        seen_ids = {id(enclosing)}
        for _ in range(max_depth):
            sites = self.callers_outside(current)
            if not sites:
                break
            file_rel, lineno = sites[0]
            caller_fn = self.enclosing_function(file_rel, lineno)
            if caller_fn is None:
                chain.append(
                    f"module-level call at {file_rel}:{lineno} "
                    '(e.g. `if __name__ == "__main__":` / argv entrypoint)'
                )
                break
            if id(caller_fn) in seen_ids:
                chain.append(f"{caller_fn.name} ({file_rel}:{lineno}) [cycle, stopping]")
                break
            chain.append(f"{caller_fn.name} ({file_rel}:{lineno})")
            seen_ids.add(id(caller_fn))
            current = caller_fn
        else:
            chain.append("(caller chain continues beyond depth limit)")
        return chain or ["no caller found in this repo (dead code)"]


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
        label, evidence = _grade_one(f, ctx, cg, reachable_ids, has_tools, bool(tool_nodes))
        conf = f.confidence
        if label is Reachability.REACHABLE:
            conf = _RAISE[f.confidence]
        elif label in (Reachability.UNREACHABLE, Reachability.CLI_ONLY, Reachability.UNCALLED):
            conf = _LOWER[f.confidence]
        graded.append(replace(f, reachability=label, confidence=conf,
                               reachability_evidence=evidence))
    result.findings = graded


def _grade_one(f: Finding, ctx: RepoContext, cg: CallGraph,
               reachable_ids: set[int], has_tools: bool,
               have_py_handlers: bool) -> tuple[Reachability, str]:
    if not has_tools:
        return Reachability.UNKNOWN, ""
    src = None
    for sf in ctx.files:
        if sf.rel == f.file:
            src = sf
            break
    # Non-Python surface (JS/TS/YAML/shell) or unparsed file: no AST call-graph.
    if src is None or src.tree is None or src.suffix not in (".py", ".pyw"):
        return Reachability.UNKNOWN, ""
    # Whole-file findings have no single enclosing scope to resolve.
    if f.line <= 0:
        return Reachability.UNKNOWN, ""
    enclosing = cg.enclosing_function(f.file, f.line)
    if enclosing is None:
        # Module-level code: executes at import, not attributable to a tool
        # call path. Honest UNKNOWN rather than a guess in either direction.
        return Reachability.UNKNOWN, ""
    if not have_py_handlers:
        # Tools exist only via manifest/JS — no Python handler roots to walk,
        # so we can't prove a Python call path either way.
        return Reachability.UNKNOWN, ""
    if id(enclosing) in reachable_ids:
        return Reachability.REACHABLE, ""
    # Not reachable from any registered tool. Decide the finer-grained
    # question -- "does anything at all call this?" -- unless the repo
    # contains dynamic dispatch that could hide a caller we can't see
    # (soundness over decidability: 2026-07-22, see Reachability docstring).
    if cg.dynamic_dispatch_present:
        return Reachability.UNKNOWN, ""
    callers = cg.callers_outside(enclosing)
    if callers:
        chain = cg.caller_chain(enclosing)
        evidence = ("reachable only from non-tool caller(s), never a "
                     "registered MCP tool: " + " <- ".join(chain))
        return Reachability.CLI_ONLY, evidence
    return Reachability.UNCALLED, "no caller found anywhere in the repo"
