"""Detector 5 — write-tools-on-by-default / tool-scope-creep.

MCP tools are registered via ``@mcp.tool()`` / ``@server.tool()`` decorators
(FastMCP and equivalents), a completely different shape from the Flask/FastAPI
HTTP-verb decorators ``auth_posture.py`` already checks. None of the 4
existing detectors ever look at tool registration, so a mutating tool with
zero gating sails through untouched.

This detector:

1. Finds every ``@mcp.tool()`` / ``@server.tool()``-decorated function.
2. Classifies it as *mutating* by name/verb heuristic (``write_``, ``delete_``,
   ``create_``, ``execute_``, ``run_``, ``send_``, ...) OR by body content —
   a direct dangerous sink call (subprocess/os.system/file-write/HTTP
   post-put-delete-patch/etc.), including **one hop** through a helper
   function it plainly delegates to elsewhere in the repo (the real shape of
   the operator's own fleet: a thin ``@mcp.tool()`` wrapper in ``server.py``
   that calls a decorated helper in a separate ``groups/*.py`` module — see
   github-mcp's ``write.py`` / desktop-mcp's ``groups/record.py``).
3. Flags a mutating tool with **no visible gate**: no gate decorator / env-flag
   opt-in / permission check on the tool function itself, and no gate found
   on the (one-hop) helper it delegates to.

Honesty note: gate resolution is a same-file-or-one-hop, name-based heuristic
— not a real call graph. It matches this repo's existing "same-file heuristic
only" disclosure (cross-file taint tracking is explicitly out of scope), with
one deliberate, narrow extension (a single hop through a directly-called
helper function) because that thin-wrapper-delegates-to-a-gated-helper shape
is the dominant real pattern this hazard needs to not false-positive on.
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

# --- mutating-by-name heuristic ------------------------------------------
_MUTATING_VERB = re.compile(
    r"^(write|delete|remove|create|add|update|modify|set|insert|upload|"
    r"execute|run|send|post|put|patch|restart|kill|terminate|spawn|exec|"
    r"drop|revoke|grant|rename|purge|wipe|comment)_",
    re.IGNORECASE,
)

# --- mutating-by-body heuristic (dangerous sinks) ------------------------
_MUTATING_SINK_SHORT = {
    "run", "call", "Popen", "check_output", "check_call",   # subprocess
    "system", "popen",                                       # os.system/popen
    "remove", "unlink", "rmdir", "rmtree", "move",           # filesystem delete/move
    "post", "put", "delete", "patch",                        # HTTP-mutate verbs
    "sendmail", "send_mail",                                 # messaging
}

# --- gate hints -----------------------------------------------------------
_GATE_HINT = re.compile(
    r"(gated|require[_-]?write|requires?[_-]?permission|permission[_-]?group|"
    r"group_enabled|check_permission|policy_refusal|requires?_auth|"
    r"auth_required|authz|rbac|is_authorized|verify_permission|tool_group|"
    r"write_group|input_group)",
    re.IGNORECASE,
)
_ENV_OPT_IN = re.compile(
    r"(os\.environ(\.get)?|os\.getenv)\s*\(\s*[\"'][A-Z0-9_]*"
    r"(ENABLE|ALLOW|PERMIT|OPT_IN)[A-Z0-9_]*[\"']",
    re.IGNORECASE,
)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _unparse(node: ast.AST) -> str:
    return ast.unparse(node) if hasattr(ast, "unparse") else ""


def _is_tool_decorator(deco: ast.AST) -> bool:
    target = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted(target)
    return bool(dotted) and dotted.split(".")[-1] == "tool"


def _declared_tool_name(deco: ast.AST, fallback: str) -> str:
    if isinstance(deco, ast.Call):
        for kw in deco.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return fallback


def _is_mutating_sink_call(call: ast.Call) -> bool:
    name = _dotted(call.func)
    short = name.split(".")[-1] if name else ""
    if "subprocess" in name:
        return True
    if name in ("os.system", "os.popen", "os.remove", "os.unlink", "os.rmdir"):
        return True
    if name in ("shutil.rmtree", "shutil.move"):
        return True
    if short in _MUTATING_SINK_SHORT:
        return True
    if short == "open":
        mode = None
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            mode = call.args[1].value
        for kw in call.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        if isinstance(mode, str) and any(c in mode for c in "wax"):
            return True
    return False


def _body_has_mutating_sink(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _is_mutating_sink_call(sub):
            return True
    return False


def _source_segment(f: SourceFile, node: ast.AST) -> str:
    try:
        seg = ast.get_source_segment(f.text, node)
        if seg:
            return seg
    except Exception:
        pass
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", start)
    if start is None:
        return ""
    return "\n".join(f.lines[start - 1:end])


def _node_has_gate(f: SourceFile, node: ast.AST) -> bool:
    deco_src = " ".join(_unparse(d) for d in getattr(node, "decorator_list", []))
    if _GATE_HINT.search(deco_src):
        return True
    body_src = _source_segment(f, node)
    return bool(_GATE_HINT.search(body_src) or _ENV_OPT_IN.search(body_src))


def _module_level_env_gate(f: SourceFile) -> bool:
    """A top-level ``if not <env opt-in>: raise/return/sys.exit`` guard."""
    if f.tree is None:
        return False
    for node in f.tree.body:
        if isinstance(node, ast.If):
            cond_src = _unparse(node.test)
            if _ENV_OPT_IN.search(cond_src) or _GATE_HINT.search(cond_src):
                return True
    return False


class ToolScopeCreepDetector(Detector):
    name = "tool-scope-creep"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        func_index = self._build_function_index(ctx)
        gated_names = self._build_gate_index(func_index)

        for f in ctx.files:
            if f.tree is None:
                continue
            module_gate = _module_level_env_gate(f)
            for node in ast.walk(f.tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                tool_deco = None
                for deco in node.decorator_list:
                    if _is_tool_decorator(deco):
                        tool_deco = deco
                        break
                if tool_deco is None:
                    continue

                tool_name = _declared_tool_name(tool_deco, node.name)
                by_name = bool(_MUTATING_VERB.match(tool_name)) or bool(_MUTATING_VERB.match(node.name))
                sink_hit, indirect_gate = self._inspect_body(node, func_index, gated_names)
                is_mutating = by_name or sink_hit
                if not is_mutating:
                    continue

                gated = _node_has_gate(f, node) or indirect_gate or module_gate
                if gated:
                    continue

                sev = Severity.P1 if sink_hit else Severity.P2
                conf = Confidence.HIGH if sink_hit else Confidence.MEDIUM
                findings.append(Finding(
                    vuln_class=self.name,
                    title=f"Mutating tool '{tool_name}' has no visible permission gate",
                    severity=sev, confidence=conf,
                    file=f.rel, line=node.lineno,
                    detail=(
                        f"'{tool_name}' is registered as an MCP tool and looks mutating "
                        f"({'a dangerous sink is reachable from its body' if sink_hit else 'by its name'}), "
                        "but neither the tool function, its file, nor a directly-called "
                        "helper shows a permission-group gate, env-flag opt-in, or "
                        "explicit auth check. Any caller (the LLM, or anything that can "
                        "reach this MCP server) can invoke it unconditionally."
                    ),
                    remediation=(
                        "Gate every mutating tool behind an explicit, default-OFF "
                        "env flag and/or permission-group check enforced at the "
                        "function level (not just documented) — e.g. a "
                        "`@gated_write`-style decorator on the tool or the helper "
                        "it calls, checked before any side effect runs."
                    ),
                    snippet=f.line_at(node.lineno),
                ))
        return findings

    # --- helpers ------------------------------------------------------
    def _inspect_body(self, node: ast.AST, func_index: dict, gated_names: set) -> tuple[bool, bool]:
        """Return (sink_hit, indirect_gate) considering one hop through any
        helper function this tool's body plainly calls by name."""
        sink_hit = _body_has_mutating_sink(node)
        indirect_gate = False
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            dotted = _dotted(sub.func)
            short = dotted.split(".")[-1] if dotted else ""
            if not short or short not in func_index:
                continue
            for _cf, cnode in func_index[short]:
                if cnode is node:
                    continue
                if not sink_hit and _body_has_mutating_sink(cnode):
                    sink_hit = True
                if short in gated_names:
                    indirect_gate = True
        return sink_hit, indirect_gate

    def _build_function_index(self, ctx: RepoContext) -> dict:
        idx: dict[str, list[tuple[SourceFile, ast.AST]]] = {}
        for f in ctx.files:
            if f.tree is None:
                continue
            for node in ast.walk(f.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    idx.setdefault(node.name, []).append((f, node))
        return idx

    def _build_gate_index(self, func_index: dict) -> set:
        gated: set[str] = set()
        for name, entries in func_index.items():
            for f, node in entries:
                if _node_has_gate(f, node):
                    gated.add(name)
                    break
        return gated
