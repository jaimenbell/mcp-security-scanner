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
from .test_paths import is_test_path
from .tool_registry import (UNROOTED_PY_SOURCES, _dotted,
                            extract_tool_registry)


# Evidence attached to the path-shape CLI_ONLY fallback (see ``_grade_one``).
# Deliberately verbose: this grade rests on the WEAKEST evidence this module
# produces, and the report must say so rather than let a reader mistake it
# for a call-graph result.
_TEST_PATH_EVIDENCE = (
    "file sits at a test/spec/fixture path, so this code is a test harness "
    "rather than a registered MCP tool entrypoint -- the same non-tool-caller "
    "category the Python call-graph pass already grades CLI_ONLY. Evidence is "
    "PATH SHAPE ONLY: no call-graph was available for this file, so this is "
    "weaker than a call-graph-derived grade and is never allowed to override "
    "one."
)


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
        name are treated as reachable — deliberately generous).

        Unchanged, deliberately: ``taint.propagate`` wants the generous set."""
        return self.reachable_from_graded(roots)[0]

    def reachable_from_graded(self, roots: list[ast.AST]) -> tuple[set[int], set[int]]:
        """``(reachable, strongly_reachable)`` from the root handlers.

        Same walk, same generosity — but it now records HOW each node was
        reached, which the single-set version threw away.

        * **reachable** — identical to ``reachable_from``. Any edge counts.
        * **strongly_reachable** — reached by a path on which EVERY edge was
          resolved exactly, i.e. caller and callee live in the same file. A
          node in ``reachable`` but not in ``strongly_reachable`` was reached
          *only* by guessing that a same-named function in some other file is
          the one being called.

        WHY (2026-08-03 hand-audit of the published ecosystem scan): the
        cross-file name guess is one-to-MANY. One production ``sandbox.run(``
        rooted in a registered tool promoted EVERY repo-wide ``run`` into the
        reachable set — including two unshipped ``_UnsafeTestSandboxProvider``
        test doubles in ``PrefectHQ/fastmcp``, which then occupied two of the
        three P0 slots in the whole gate-qualifying queue. Because REACHABLE
        is decided before the ``is_test_path`` fallback in ``_grade_one`` can
        run, and REACHABLE also fires the ``_RAISE`` confidence nudge, the
        guess inflated severity and defeated the ``--fail-on`` exclusion in
        one step.

        Keeping both sets rather than tightening the walk is the point: the
        generous edge is still followed and still reported, so nothing is
        silently dropped. Only the *grader* is told the difference, and only
        it decides what to do about a weak-only path.
        """
        visited: set[int] = set()
        strong: set[int] = set()
        # (node, reached_by_an_all-exact-path). Roots are strong by definition.
        stack: list[tuple[ast.AST, bool]] = [(r, True) for r in roots if r is not None]
        while stack:
            node, is_strong = stack.pop()
            node_id = id(node)
            # A node first reached weakly and later strongly must be expanded
            # AGAIN, so strength propagates to its callees. Re-expansion is
            # bounded: each node is expanded at most twice (once per flag).
            if is_strong:
                if node_id in strong:
                    continue
                strong.add(node_id)
            elif node_id in visited:
                continue
            visited.add(node_id)
            owner = self._node_file.get(node_id)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                dotted = _dotted(sub.func)
                short = dotted.split(".")[-1] if dotted else ""
                if not short:
                    continue
                for callee in self._by_name.get(short, []):
                    # Exact resolution == the callee lives in the caller's own
                    # file. Anything else is the best-effort repo-wide guess,
                    # so the path through it can never be strong.
                    callee_owner = self._node_file.get(id(callee))
                    edge_strong = (
                        is_strong
                        and owner is not None
                        and callee_owner == owner
                    )
                    if edge_strong:
                        if id(callee) in strong:
                            continue
                    elif id(callee) in visited:
                        continue
                    stack.append((callee, edge_strong))
        return visited, strong

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
    # 2026-07-23 round-3 N-vote fix (Opus final-verify BLOCKED finding): a
    # low-level-SDK registration with node=None (tool_registry.py couldn't
    # unambiguously attribute a same-file dispatcher -- split declaration/
    # dispatch modules, or a genuinely ambiguous multi-dispatcher file) means
    # a REAL tool exists whose call path this pass cannot walk. has_tools/
    # have_py_handlers are computed repo-wide, so as soon as ANY OTHER
    # registration in the same repo has a valid root, the CLI_ONLY/UNCALLED
    # branch below would confidently grade -- and possibly DOWNGRADE -- a
    # finding that is, in truth, reachable only through the un-rooted
    # dispatcher this pass never walked. Same treatment as
    # ``dynamic_dispatch_present``: soundness over decidability.
    #
    # 2026-07-30 (recall slice 1): broadened from the single "py-lowlevel-sdk"
    # source to ``UNROOTED_PY_SOURCES``, imported from ``tool_registry`` rather
    # than re-listed here so the set and its justification cannot drift. The
    # new ``py-call`` source (``self.tool(handler, name=...)``, mcp-server-
    # qdrant's shape) has exactly the same property: it proves a real Python
    # tool exists whose root could not be attributed without guessing.
    unrooted_py_root = any(
        r.node is None and r.source in UNROOTED_PY_SOURCES for r in registry
    )

    cg = CallGraph(ctx)
    reachable_ids, strong_ids = (
        cg.reachable_from_graded(tool_nodes) if tool_nodes else (set(), set())
    )

    graded: list[Finding] = []
    for f in result.findings:
        label, evidence = _grade_one(f, ctx, cg, reachable_ids, has_tools,
                                      bool(tool_nodes), unrooted_py_root,
                                      strong_ids)
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
               have_py_handlers: bool, unrooted_py_root: bool = False,
               strong_ids: set[int] | None = None) -> tuple[Reachability, str]:
    """Call-graph grade first; path-shape fallback only where it said UNKNOWN.

    STRICT ORDERING (2026-07-29, and the point of the split): ``_grade_ast``
    is consulted first and its answer is final whenever it decided anything.
    The path-shape fallback below is the weakest evidence this module has and
    must never outrank the strongest -- a sink proven REACHABLE from a tool
    root does not stop being reachable because its file is named
    ``*.test.py``.

    THAT ORDERING STANDS. What changed on 2026-08-03 is the definition of
    "proven": a path made of best-effort cross-file NAME GUESSES was never
    proof, and it was outranking the fallback on the strength of a guess.
    ``_grade_ast`` now declines to call such a path REACHABLE *when the file
    is also a test path* -- both conditions, never either alone -- so the
    fallback gets asked the question it was written to answer. Real evidence
    still wins; a guess no longer counts as real evidence.
    """
    label, evidence = _grade_ast(f, ctx, cg, reachable_ids, has_tools,
                                 have_py_handlers, unrooted_py_root,
                                 strong_ids)
    if label is not Reachability.UNKNOWN:
        return label, evidence
    # Nothing decidable from the call-graph -- for a non-Python surface that
    # is EVERY finding, which is how ~30 of the 58 false positives in the
    # 2026-07-29 measurement were test-harness code presented as production
    # attack surface. ``Reachability.CLI_ONLY``'s own definition already
    # names "a test file" as a non-tool entrypoint, so this reuses that grade
    # (and with it the existing confidence nudge and --fail-on exclusion)
    # rather than inventing a parallel mechanism.
    if is_test_path(f.file):
        return Reachability.CLI_ONLY, _TEST_PATH_EVIDENCE
    return Reachability.UNKNOWN, ""


def _grade_ast(f: Finding, ctx: RepoContext, cg: CallGraph,
               reachable_ids: set[int], has_tools: bool,
               have_py_handlers: bool, unrooted_py_root: bool = False,
               strong_ids: set[int] | None = None) -> tuple[Reachability, str]:
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
        # SCOPE, STATED WITH THE PATTERN (2026-08-03). Decline REACHABLE only
        # where BOTH hold: the sink was reached SOLELY through best-effort
        # cross-file name guesses (never an exactly-resolved same-file edge on
        # any path from a root), AND the file is a test path. Either condition
        # alone changes nothing:
        #   * weak-only path in PRODUCTION code -> still REACHABLE. Recall on
        #     the surface that matters is untouched, which is the whole reason
        #     this is a two-condition rule and not a tightening of the walk.
        #   * test path reached by a REAL same-file edge -> still REACHABLE,
        #     which is the ordering pinned by
        #     ``test_path_shape_never_overrides_a_real_call_graph_grade``.
        # Returning UNKNOWN (not CLI_ONLY) keeps this function honest about
        # what it knows and hands the decision to the existing path-shape
        # fallback in ``_grade_one``, reusing that mechanism rather than
        # inventing a parallel one.
        weak_only = strong_ids is not None and id(enclosing) not in strong_ids
        if weak_only and is_test_path(f.file):
            return Reachability.UNKNOWN, ""
        return Reachability.REACHABLE, ""
    # Not reachable from any registered tool. Decide the finer-grained
    # question -- "does anything at all call this?" -- unless the repo
    # contains dynamic dispatch that could hide a caller we can't see
    # (soundness over decidability: 2026-07-22, see Reachability docstring),
    # or an un-rooted low-level-SDK dispatcher exists in this same repo that
    # this pass never walked (soundness over decidability: 2026-07-23 round-3
    # N-vote fix -- see the ``unrooted_py_root`` comment in grade_result).
    if cg.dynamic_dispatch_present or unrooted_py_root:
        return Reachability.UNKNOWN, ""
    callers = cg.callers_outside(enclosing)
    if callers:
        chain = cg.caller_chain(enclosing)
        evidence = ("reachable only from non-tool caller(s), never a "
                     "registered MCP tool: " + " <- ".join(chain))
        return Reachability.CLI_ONLY, evidence
    return Reachability.UNCALLED, "no caller found anywhere in the repo"
