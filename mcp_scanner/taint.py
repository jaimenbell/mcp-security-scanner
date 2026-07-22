"""Tool-parameter taint tracking (post-detector pass).

The reachability pass (``reachability.py``) answers *"is this flagged code
reachable from a registered MCP tool?"*. It does not answer the sharper
question: *"does a TOOL-PARAMETER's value actually flow into the dangerous
sink?"*. A sink sitting inside a reachable tool handler but fed only a
hard-coded constant is a very different risk from one fed the caller's raw
argument -- yet reachability grades both the same.

This pass closes that gap, statically:

  1. Seed every registered Python tool handler's parameters as taint SOURCES
     (via the shared ``tool_registry`` extractor -- same roots reachability
     uses).
  2. Propagate taint through assignments, f-strings / string concat / ``%`` /
     ``.format()``, common containers (list/tuple/dict/set, subscript,
     attribute) and same-repo function calls -- transitively within a file,
     and up to TWO direct-import hops into other same-repo modules (Slice 2
     shipped one hop; Slice 3 raised the budget to two).
  3. Sinks are the param-injection detector's dangerous calls
     (subprocess/os.system/eval/exec/pickle/yaml.load/HTTP-fetch/open). Label
     each such finding TAINTED / UNTAINTED / UNKNOWN and nudge confidence up
     (TAINTED) or down (UNTAINTED). It NEVER drops a finding.

Honest boundary (stated on the report): same-file dataflow is transitive;
cross-file follows up to TWO direct-import hops (no third hop, no
decorator-transform tracking, no dynamic dispatch / ``getattr`` / ``*args``
re-binding). Non-Python findings, module-level code, code unreachable from
any tool, and non-dataflow detector classes are labelled UNKNOWN rather than
guessed.
"""

from __future__ import annotations

import ast
from dataclasses import replace

from .detectors.base import RepoContext, SourceFile
from .models import Confidence, Finding, ScanResult, Taint
from .reachability import CallGraph
from .tool_registry import _dotted, extract_tool_registry

# --------------------------------------------------------------------- #
# Confidence nudge tables -- TAINTED raises, UNTAINTED lowers, never drops.
# Mirrors reachability's tables; UNKNOWN leaves confidence untouched.
# --------------------------------------------------------------------- #
_RAISE = {Confidence.LOW: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.HIGH,
          Confidence.HIGH: Confidence.HIGH}
_LOWER = {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW,
          Confidence.LOW: Confidence.LOW}

# Only these detector classes are dataflow-shaped (a tool argument flowing into
# a sink). Every other finding class is left UNKNOWN by this pass.
_DATAFLOW_CLASSES = {
    "shell-injection", "code-eval", "unsafe-deserialization", "ssrf",
    "path-traversal",
}

# Cross-file propagation, up to two direct-import hops (Slice 3; Slice 2
# shipped one hop). Same-file dataflow is transitive; from a tool-reachable
# function we follow import hops into other same-repo modules and propagate
# through each callee's params to its sinks. No third hop, no
# decorator-transform tracking, no dynamic dispatch (getattr / *args /
# **kwargs re-binding) -- all stated as honest limits.
_CROSS_FILE = True
_CROSS_FILE_HOP_BUDGET = 2


# --------------------------------------------------------------------- #
# Expression taint test
# --------------------------------------------------------------------- #
def _expr_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    """True if evaluating ``node`` can carry a tainted value.

    Deliberately generous (over-taint rather than miss): any tainted sub-part of
    a concat / f-string / container / call-argument makes the whole expression
    tainted. Sanitizers are NOT modelled -- a call that receives a tainted arg
    is treated as still tainted, matching the scanner's over-flag philosophy.
    """
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(_expr_tainted(v, tainted) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.BinOp):  # a + b, a % b, ...
        return _expr_tainted(node.left, tainted) or _expr_tainted(node.right, tainted)
    if isinstance(node, ast.BoolOp):
        return any(_expr_tainted(v, tainted) for v in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_tainted(e, tainted) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_expr_tainted(k, tainted) for k in node.keys if k is not None) \
            or any(_expr_tainted(v, tainted) for v in node.values)
    if isinstance(node, ast.Subscript):
        return _expr_tainted(node.value, tainted) or _expr_tainted(node.slice, tainted)
    if isinstance(node, ast.Attribute):
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.Starred):
        return _expr_tainted(node.value, tainted)
    if isinstance(node, (ast.IfExp,)):
        return _expr_tainted(node.body, tainted) or _expr_tainted(node.orelse, tainted)
    if isinstance(node, ast.Call):
        # `"x {}".format(tainted)`, `str(tainted)`, `sanitize(tainted)` -- any
        # tainted argument (or a tainted receiver, e.g. `tainted.strip()`) taints
        # the result. We do NOT trust sanitizers to clean taint.
        if _expr_tainted(node.func, tainted):
            return True
        if any(_expr_tainted(a, tainted) for a in node.args):
            return True
        if any(_expr_tainted(kw.value, tainted) for kw in node.keywords):
            return True
        return False
    return False


def _target_names(node: ast.AST) -> list[str]:
    """Bare ``Name`` targets of an assignment (tuple/list unpacking recursed)."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        out: list[str] = []
        for e in node.elts:
            out.extend(_target_names(e))
        return out
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return []  # Subscript/Attribute targets intentionally not tracked


# --------------------------------------------------------------------- #
# Intra-function fixpoint: which local names become tainted given seed params
# --------------------------------------------------------------------- #
def _tainted_names_in_func(func: ast.AST, seed: set[str]) -> set[str]:
    tainted = set(seed)
    changed = True
    while changed:
        changed = False
        for n in ast.walk(func):
            newly: list[str] = []
            if isinstance(n, ast.Assign):
                if _expr_tainted(n.value, tainted):
                    for t in n.targets:
                        newly.extend(_target_names(t))
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                if _expr_tainted(n.value, tainted):
                    newly.extend(_target_names(n.target))
            elif isinstance(n, ast.AugAssign):
                if _expr_tainted(n.value, tainted) or _expr_tainted(n.target, tainted):
                    newly.extend(_target_names(n.target))
            elif isinstance(n, ast.NamedExpr):  # walrus :=
                if _expr_tainted(n.value, tainted):
                    newly.extend(_target_names(n.target))
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                if _expr_tainted(n.iter, tainted):
                    newly.extend(_target_names(n.target))
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars is not None and _expr_tainted(item.context_expr, tainted):
                        newly.extend(_target_names(item.optional_vars))
            for name in newly:
                if name not in tainted:
                    tainted.add(name)
                    changed = True
    return tainted


# --------------------------------------------------------------------- #
# Cross-function taint propagation (worklist over the call graph)
# --------------------------------------------------------------------- #
class TaintEngine:
    """Propagate tool-parameter taint across the repo's function call graph.

    ``computed`` maps a function node id -> the set of tainted local names in
    that function, for every function the propagation reached from a tool root.
    """

    def __init__(self, ctx: RepoContext) -> None:
        self._funcs_by_rel: dict[str, list[ast.AST]] = {}
        self._funcs_by_name_in_rel: dict[str, dict[str, list[ast.AST]]] = {}
        self._node_file: dict[int, str] = {}
        # Repo-wide name index + per-file import maps for Slice-2 cross-file hop.
        self._by_name: dict[str, list[ast.AST]] = {}
        self._imports_by_rel: dict[str, dict[str, str]] = {}
        for f in ctx.files:
            if f.tree is None:
                continue
            funcs: list[ast.AST] = []
            by_name: dict[str, list[ast.AST]] = {}
            for node in ast.walk(f.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.append(node)
                    by_name.setdefault(node.name, []).append(node)
                    self._by_name.setdefault(node.name, []).append(node)
                    self._node_file[id(node)] = f.rel
            self._funcs_by_rel[f.rel] = funcs
            self._funcs_by_name_in_rel[f.rel] = by_name
            self._imports_by_rel[f.rel] = self._import_map(f.tree)
        self.computed: dict[int, set[str]] = {}

    @staticmethod
    def _import_map(tree: ast.AST) -> dict[str, str]:
        """local-name -> imported symbol name, for `from x import f [as g]`.

        Only bare `from ... import name` symbols are tracked (the shape we can
        resolve one hop by name). `import x` / `import x as y` module aliases
        are recorded too so `x.f(...)` can be name-resolved.
        """
        out: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    out[alias.asname or alias.name] = alias.name
        return out

    @staticmethod
    def _param_names(func: ast.AST) -> list[str]:
        a = func.args
        names = [p.arg for p in a.posonlyargs] + [p.arg for p in a.args]
        names += [p.arg for p in a.kwonlyargs]
        return names

    def _resolve_callee(self, call: ast.Call, caller_rel: str, allow_cross: bool):
        """Return list of (callee_node, is_cross_file) for a call site."""
        dotted = _dotted(call.func)
        short = dotted.split(".")[-1] if dotted else ""
        if not short:
            return []
        out = []
        # Same-file first (exact scope match, generous by name).
        same = self._funcs_by_name_in_rel.get(caller_rel, {}).get(short, [])
        for node in same:
            out.append((node, False))
        if out:
            return out
        if not allow_cross:
            return []
        # Slice 2: one import hop. Resolve the short name repo-wide, but only if
        # it was directly imported into the caller's file (honest one-hop).
        imported = self._imports_by_rel.get(caller_rel, {})
        target_name = imported.get(short, short if dotted != short else None)
        # `x.f()` where `x` is an imported module -> resolve `f` repo-wide.
        if target_name is None and "." in dotted:
            target_name = short
        if target_name is None:
            return []
        for node in self._by_name.get(target_name, []):
            if self._node_file.get(id(node)) != caller_rel:  # genuinely cross-file
                out.append((node, True))
        return out

    def propagate(self, roots: list[ast.AST]) -> None:
        # Each work item: (func_node, seed_tainted_params, cross_budget)
        stack: list[tuple[ast.AST, frozenset[str], int]] = []
        seeds: dict[int, set[str]] = {}
        for r in roots:
            if r is None:
                continue
            params = set(self._param_names(r))
            seeds[id(r)] = set(params)
            stack.append((r, frozenset(params), _CROSS_FILE_HOP_BUDGET))
        while stack:
            node, seed, budget = stack.pop()
            cur = seeds.setdefault(id(node), set())
            merged = cur | set(seed)
            already = id(node) in self.computed
            if already and merged == cur:
                continue  # no growth -> nothing new to propagate
            seeds[id(node)] = merged
            tnames = _tainted_names_in_func(node, merged)
            self.computed[id(node)] = tnames
            caller_rel = self._node_file.get(id(node), "")
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                allow_cross = _CROSS_FILE and budget > 0
                callees = self._resolve_callee(sub, caller_rel, allow_cross)
                for callee, is_cross in callees:
                    passed = self._tainted_params_passed(sub, callee, tnames)
                    new_budget = (budget - 1) if is_cross else budget
                    stack.append((callee, frozenset(passed), new_budget))

    def _tainted_params_passed(self, call: ast.Call, callee: ast.AST,
                               tnames: set[str]) -> set[str]:
        """Which of ``callee``'s params receive a tainted argument at ``call``."""
        params = self._param_names(callee)
        out: set[str] = set()
        for i, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                continue  # *args re-binding not modelled (stated limit)
            if i < len(params) and _expr_tainted(arg, tnames):
                out.add(params[i])
        pset = set(params)
        for kw in call.keywords:
            if kw.arg is None:
                continue  # **kwargs not modelled
            if kw.arg in pset and _expr_tainted(kw.value, tnames):
                out.add(kw.arg)
        return out


# --------------------------------------------------------------------- #
# Grading entry point
# --------------------------------------------------------------------- #
def grade_result(ctx: RepoContext, result: ScanResult) -> None:
    """In-place: label every finding with a tool-parameter taint grade and
    nudge confidence. TAINTED raises, UNTAINTED lowers, UNKNOWN untouched. Never
    drops a finding."""
    registry = extract_tool_registry(ctx)
    tool_nodes = [r.node for r in registry if r.node is not None]
    has_tools = bool(registry)
    have_py_handlers = bool(tool_nodes)

    cg = CallGraph(ctx)
    reachable_ids = cg.reachable_from(tool_nodes) if tool_nodes else set()

    engine = TaintEngine(ctx)
    if tool_nodes:
        engine.propagate(tool_nodes)

    graded: list[Finding] = []
    for f in result.findings:
        label = _grade_one(f, ctx, cg, engine, reachable_ids,
                           has_tools, have_py_handlers)
        conf = f.confidence
        if label is Taint.TAINTED:
            conf = _RAISE[f.confidence]
        elif label is Taint.UNTAINTED:
            conf = _LOWER[f.confidence]
        graded.append(replace(f, taint=label, confidence=conf))
    result.findings = graded


def _grade_one(f: Finding, ctx: RepoContext, cg: CallGraph, engine: TaintEngine,
               reachable_ids: set[int], has_tools: bool,
               have_py_handlers: bool) -> Taint:
    if f.vuln_class not in _DATAFLOW_CLASSES:
        return Taint.UNKNOWN
    if not has_tools or not have_py_handlers:
        return Taint.UNKNOWN
    src: SourceFile | None = None
    for sf in ctx.files:
        if sf.rel == f.file:
            src = sf
            break
    if src is None or src.tree is None or src.suffix not in (".py", ".pyw"):
        return Taint.UNKNOWN
    if f.line <= 0:
        return Taint.UNKNOWN
    enclosing = cg.enclosing_function(f.file, f.line)
    if enclosing is None:  # module-level code -- no tool call path to attribute
        return Taint.UNKNOWN
    if id(enclosing) not in reachable_ids:  # unreachable: reachability's axis
        return Taint.UNKNOWN
    tnames = engine.computed.get(id(enclosing))
    if tnames is None:  # reachable but taint pass never analyzed it -> honest unknown
        return Taint.UNKNOWN
    # Is any positional (data) argument of a call on this line tainted?
    calls = [n for n in ast.walk(enclosing)
             if isinstance(n, ast.Call) and getattr(n, "lineno", None) == f.line]
    if not calls:
        return Taint.UNKNOWN
    for c in calls:
        for arg in c.args:
            if _expr_tainted(arg, tnames):
                return Taint.TAINTED
    return Taint.UNTAINTED
