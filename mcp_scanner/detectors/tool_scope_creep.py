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

Low-level MCP SDK coverage (2026-07-23): this detector used to consume only
``extract_tool_registry``'s ``source == "js-regex"`` entries and re-derive
its own decorator walk directly for Python — a repo using ONLY the low-level
SDK shape (``Server()`` + a single ``@server.call_tool()`` dispatch function,
no ``@mcp.tool()`` decorators anywhere) got zero coverage regardless of how
many ungated mutating tools it registered. Fixed via
``tool_registry.dispatch_segments``: for each file gated on
``_file_imports_mcp`` with exactly one ``@server.call_tool()`` handler (zero
or ambiguous -> skip, never guess a root), the handler body is split into
per-tool branches (the "effective body" scope-creep analysis needs). A
branch attributable to one specific literal tool name (``if name == "x":``)
is classified/attributed to that tool exactly like a decorator-registered
one; a branch that isn't (an ``in (...)`` test, the final ``else``, code
outside the if/elif chain, or no dispatch shape at all) is attributed to the
dispatch handler itself — never a guessed tool name — mirroring
``secret_leak_response.py``'s identical low-level-SDK extension. Known
boundary, disclosed rather than silently left: only a literal ``==`` if/elif
walk is recognized as attributable dispatch; a dict-keyed dispatch table or
``match``/``case`` statement falls back to whole-handler attribution. A gate
found anywhere in the handler's own decorator/body text (module-level env
gate, or a shared pre-dispatch permission check that runs before every
branch) is treated as gating every branch in that handler — a deliberately
coarse, disclosed heuristic (same breadth already accepted for the existing
module-level gate), not per-branch dataflow proof.
"""

from __future__ import annotations

import ast
import re
import tokenize
import io

from ..models import Finding, Severity, Confidence
from ..tool_registry import (
    _dotted,
    _is_tool_decorator,
    _declared_tool_name,
    extract_tool_registry,
    _is_call_tool_decorator,
    _file_imports_mcp,
    _decorated_in_file,
    dispatch_segments,
)
from .. import js_util
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

# --- JS/TS parity ----------------------------------------------------------
# No AST for JS/TS in this scanner (see js_util). Tool bodies aren't
# delimited without a parser, so the "body" a JS tool is graded on is a
# capped line window from its registration to the next registration (or 40
# lines, whichever is shorter) -- a same-file, no-real-scope heuristic,
# consistent with this detector's existing one-hop/name-based honesty note.
_JS_MUTATING_SINK = re.compile(
    r"\b(?:child_process\.)?(?:exec|execSync|spawn|execFile)(?:Sync)?\s*\(|"
    r"\bfs\.(?:unlink|rmdir|rm|writeFile|appendFile)(?:Sync)?\s*\(|"
    r"\baxios\.(?:post|put|delete|patch)\s*\(|"
    r"\bfetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|DELETE|PATCH)[\"']|"
    r"\bprocess\.kill\s*\(|"
    r"\bsendMail\s*\(",
    re.IGNORECASE,
)
_JS_ENV_OPT_IN = re.compile(
    r"process\.env(?:\.|\[)\s*[\"']?[A-Z0-9_]*(ENABLE|ALLOW|PERMIT|OPT_IN)[A-Z0-9_]*",
    re.IGNORECASE,
)
_JS_WINDOW_MAX_LINES = 40


def _unparse(node: ast.AST) -> str:
    return ast.unparse(node) if hasattr(ast, "unparse") else ""


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


def _strip_py_comments(src: str) -> str:
    """Best-effort comment-stripped copy of ``src`` so a ``# TODO: needs
    auth_required check`` comment never counts as gate evidence (P0 fix --
    comment text was previously indistinguishable from real gate code to the
    ``_GATE_HINT``/``_ENV_OPT_IN`` regex search). Falls back to the original
    text if tokenizing fails (e.g. an indented source segment -- a method
    body sliced out on its own -- isn't independently tokenizable); that
    fallback is no worse than the prior behavior, never better."""
    try:
        lines = src.splitlines(keepends=True)
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type != tokenize.COMMENT:
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            if srow == erow and 0 < srow <= len(lines):
                line = lines[srow - 1]
                lines[srow - 1] = line[:scol] + line[ecol:]
        return "".join(lines)
    except Exception:
        return src


def _node_has_gate(f: SourceFile, node: ast.AST) -> bool:
    deco_src = " ".join(_unparse(d) for d in getattr(node, "decorator_list", []))
    if _GATE_HINT.search(deco_src):
        return True
    body_src = _strip_py_comments(_source_segment(f, node))
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
            if _file_imports_mcp(f):
                findings.extend(self._scan_low_level_sdk(f, func_index, gated_names))
        findings.extend(self._scan_js(ctx))
        return findings

    # --- low-level MCP SDK: call_tool dispatch handler --------------------
    def _scan_low_level_sdk(self, f: SourceFile, func_index: dict, gated_names: set) -> list[Finding]:
        handlers = _decorated_in_file(f, _is_call_tool_decorator)
        if len(handlers) != 1:
            # Zero, or more than one, call_tool handler in this file --
            # never guess a root (mirrors _extract_low_level_sdk).
            return []
        handler = handlers[0]
        module_gate = _module_level_env_gate(f)
        # Deliberately coarse (disclosed): a gate hint anywhere in the
        # handler's own decorator list or full body text -- covers a shared
        # pre-dispatch permission check that runs before every branch --
        # gates every branch in this handler, not just the segment it's
        # textually in.
        shared_gate = module_gate or _node_has_gate(f, handler)

        out: list[Finding] = []
        for tool_name, stmts in dispatch_segments(handler):
            sink_hit, indirect_gate = self._inspect_stmts(stmts, func_index, gated_names)
            by_name = bool(tool_name) and bool(_MUTATING_VERB.match(tool_name))
            is_mutating = by_name or sink_hit
            if not is_mutating:
                continue

            gated = shared_gate or indirect_gate or self._stmts_have_gate(f, stmts)
            if gated:
                continue

            sev = Severity.P1 if sink_hit else Severity.P2
            conf = Confidence.HIGH if sink_hit else Confidence.MEDIUM
            line = stmts[0].lineno if stmts else handler.lineno
            if tool_name:
                subject = f"Tool '{tool_name}'"
                title = f"Mutating tool '{tool_name}' has no visible permission gate"
            else:
                subject = f"An unattributed branch of the '{handler.name}' dispatch handler"
                title = (
                    f"Mutating branch of low-level dispatch handler '{handler.name}' "
                    "has no visible permission gate (tool not attributable)"
                )
            out.append(Finding(
                vuln_class=self.name,
                title=title,
                severity=sev, confidence=conf,
                file=f.rel, line=line,
                detail=(
                    f"{subject} looks mutating "
                    f"({'a dangerous sink is reachable from its body' if sink_hit else 'by its name'}), "
                    "but no permission-group gate, env-flag opt-in, or explicit auth check is "
                    "visible on the dispatch handler, this branch, or a directly-called helper. "
                    "Any caller (the LLM, or anything that can reach this MCP server) can invoke "
                    "it unconditionally."
                ),
                remediation=(
                    "Gate every mutating tool behind an explicit, default-OFF env flag and/or "
                    "permission-group check enforced before any side effect runs — e.g. a shared "
                    "check at the top of the dispatch handler, or per-branch, checked before the "
                    "sink executes."
                ),
                snippet=f.line_at(line),
            ))
        return out

    def _inspect_stmts(self, stmts: list[ast.stmt], func_index: dict, gated_names: set) -> tuple[bool, bool]:
        """Same one-hop helper-delegation logic as ``_inspect_body``, scoped
        to a ``dispatch_segments`` branch (a list of statements) instead of a
        single function node."""
        sink_hit = any(_body_has_mutating_sink(s) for s in stmts)
        indirect_gate = False
        for stmt in stmts:
            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue
                dotted = _dotted(sub.func)
                short = dotted.split(".")[-1] if dotted else ""
                if not short or short not in func_index:
                    continue
                for _cf, cnode in func_index[short]:
                    if not sink_hit and _body_has_mutating_sink(cnode):
                        sink_hit = True
                    if short in gated_names:
                        indirect_gate = True
        return sink_hit, indirect_gate

    def _stmts_have_gate(self, f: SourceFile, stmts: list[ast.stmt]) -> bool:
        if not stmts:
            return False
        body_src = _strip_py_comments("\n".join(_source_segment(f, s) for s in stmts))
        return bool(_GATE_HINT.search(body_src) or _ENV_OPT_IN.search(body_src))

    # --- JS/TS: line-window sink/gate regex (no AST available) -----------
    def _scan_js(self, ctx: RepoContext) -> list[Finding]:
        regs = [r for r in extract_tool_registry(ctx) if r.source == "js-regex"]
        if not regs:
            return []
        by_file: dict[str, list] = {}
        for r in regs:
            by_file.setdefault(r.file, []).append(r)

        out: list[Finding] = []
        for f in ctx.files:
            if f.rel not in by_file:
                continue
            regs_in_file = sorted(by_file[f.rel], key=lambda r: r.line)
            for idx, r in enumerate(regs_in_file):
                start = r.line
                next_line = (
                    regs_in_file[idx + 1].line if idx + 1 < len(regs_in_file) else len(f.lines) + 1
                )
                end = min(next_line - 1, start + _JS_WINDOW_MAX_LINES, len(f.lines))
                window_lines = f.lines[start - 1:end]
                window = "\n".join(window_lines)
                # Comment-stripped copy used ONLY for gate-hint matching (P0
                # fix): a '// TODO: needs auth_required check' comment must
                # never count as gate evidence. Sink matching stays on the
                # raw window -- a sink pattern glued inside a comment is an
                # over-flag, the direction this scanner already accepts.
                gate_window = "\n".join(
                    js_util.code_part(raw) for raw in window_lines
                    if not js_util.is_comment_line(raw)
                )

                tool_label = r.name if r.name and r.name != "(inline)" else "(unnamed tool)"
                by_name = bool(_MUTATING_VERB.match(tool_label))
                sink_hit = bool(_JS_MUTATING_SINK.search(window))
                if not (by_name or sink_hit):
                    continue

                gated = bool(_GATE_HINT.search(gate_window)) or bool(_JS_ENV_OPT_IN.search(gate_window))
                if gated:
                    continue

                sev = Severity.P1 if sink_hit else Severity.P2
                conf = Confidence.HIGH if sink_hit else Confidence.MEDIUM
                out.append(Finding(
                    vuln_class=self.name,
                    title=f"Mutating tool '{tool_label}' has no visible permission gate",
                    severity=sev, confidence=conf,
                    file=f.rel, line=r.line,
                    detail=(
                        f"'{tool_label}' is registered as an MCP tool (JS/TS "
                        f"regex-detected) and looks mutating "
                        f"({'a dangerous sink appears in its body window' if sink_hit else 'by its name'}), "
                        "but no permission-group gate or env-flag opt-in was found in "
                        "the line window from its registration to the next tool "
                        "registration (or 40 lines, whichever is shorter -- there is "
                        "no JS/TS AST in this scanner to delimit the real function "
                        "body)."
                    ),
                    remediation=(
                        "Gate every mutating tool behind an explicit, default-OFF "
                        "env flag and/or permission-group check enforced before any "
                        "side effect runs."
                    ),
                    snippet=f.line_at(r.line),
                ))
        return out

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
