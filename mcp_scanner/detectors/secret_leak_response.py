"""Detector 6 — secret-leak-via-tool-response.

``secret_handling.py`` only checks secrets at rest (tracked files, hardcoded
literals) and secrets passed to ``print``/``log.*``. It never inspects what a
tool handler actually hands back to the *calling LLM* through the MCP
protocol — a distinct leak surface: a tool can be perfectly fine about not
logging a credential and still return it verbatim in its response payload.

This detector walks every ``@mcp.tool()``/``@server.tool()``-decorated
function's ``return`` expression(s) and flags a leak-shaped value when the
returned dict/tuple/list/bare-expression includes, at a leaf value position:

* ``os.environ`` itself (the whole environment dumped back to the caller);
* a whole config/settings object returned wholesale (``return config``,
  ``vars(config)``, ``config.__dict__``, ``dataclasses.asdict(config)``);
* a variable/attribute whose name matches the secret-name heuristic, or a
  dict key literal that does;
* a hardcoded secret-shaped string literal (reuses ``secret_handling.py``'s
  own value-pattern list directly).

Reuse, not reinvention: the secret-name vocabulary is the exact
``_SECRET_NAME`` regex object imported from ``secret_handling.py`` (per the
spec's own note that it is "directly reusable"). The only new logic here is
a *word-boundary-aware* wrapper around it (``_name_looks_secret``) — the bare
regex is a substring search with no notion of word boundaries, so applied to
an identifier as-is it would flag names like ``tokenizer_version`` or
``passwordless_mode`` (contains "token"/"password" as a *glued* substring,
not a real secret). The wrapper rejects a match only when it is glued to
more letters on either side with no separator/case-boundary between them —
a legitimate whole-word hit like ``SECRET_KEY`` or ``api_key`` still fires.
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .. import js_util
from ..tool_registry import extract_tool_registry
from .base import Detector, RepoContext, SourceFile
from .secret_handling import _SECRET_NAME, _SECRET_VALUE_PATTERNS, _JS_STRING_LITERAL

_WHOLE_OBJECT_NAME = {"config", "settings", "cfg", "conf", "env", "environment", "secrets"}

# --- JS/TS parity ------------------------------------------------------
# No AST for JS/TS in this scanner. Same registration-window heuristic as
# tool_scope_creep.py's JS path (registration line -> next registration, or
# 40 lines, whichever is shorter), scanned for `return` shapes with a small
# brace-depth tracker for the object-literal case -- line-based, not a real
# parser.
_JS_WINDOW_MAX_LINES = 40
_JS_RETURN_ENV = re.compile(r"\breturn\s+process\.env\b")
_JS_RETURN_WHOLE_OBJECT_NAME = re.compile(
    r"\breturn\s+(?:\{\s*\.\.\.)?\s*(config|settings|cfg|conf|env|environment|secrets)\b",
    re.IGNORECASE,
)
_JS_BARE_RETURN_NAME = re.compile(r"\breturn\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;")
_JS_OBJECT_KEY = re.compile(r"^\s*[\"']?([A-Za-z_$][A-Za-z0-9_$]*)[\"']?\s*:\s*(.+?),?\s*$")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _name_looks_secret(name: str) -> bool:
    """``_SECRET_NAME`` (reused as-is) with a word-boundary guard so a
    substring glued inside a longer, unrelated word doesn't count."""
    if not name:
        return False
    m = _SECRET_NAME.search(name)
    if not m:
        return False
    start, end = m.span()
    before = name[start - 1] if start > 0 else ""
    after = name[end] if end < len(name) else ""
    if before.isalpha() and before.islower():
        return False
    if after.isalpha() and after.islower():
        return False
    return True


def _is_tool_decorator(deco: ast.AST) -> bool:
    target = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted(target)
    return bool(dotted) and dotted.split(".")[-1] == "tool"


def _leaf_values(expr: ast.AST) -> list[ast.AST]:
    """The value-position leaves of a returned dict/tuple/list, or the
    expression itself if it isn't one of those containers."""
    if isinstance(expr, ast.Dict):
        return [v for v in expr.values if v is not None]
    if isinstance(expr, (ast.Tuple, ast.List)):
        return list(expr.elts)
    return [expr]


def _dict_keys(expr: ast.AST) -> list[ast.AST]:
    if isinstance(expr, ast.Dict):
        return [k for k in expr.keys if k is not None]
    return []


def _direct_returns(node: ast.AST):
    """Yield Return nodes belonging to *this* function — do not descend into
    a nested def/lambda (its returns belong to the nested function, not the
    tool handler itself)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Return):
            yield child
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        else:
            yield from _direct_returns(child)


class SecretLeakResponseDetector(Detector):
    name = "secret-leak-via-tool-response"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        for f in ctx.files:
            if f.tree is None:
                continue
            for node in ast.walk(f.tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not any(_is_tool_decorator(d) for d in node.decorator_list):
                    continue
                for ret in _direct_returns(node):
                    if ret.value is None:
                        continue
                    findings.extend(self._check_return(f, node, ret))
        findings.extend(self._scan_js(ctx))
        return findings

    # --- JS/TS: registration-window return regex (no AST available) ------
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
                tool_label = r.name if r.name and r.name != "(inline)" else "(unnamed tool)"
                out.extend(self._check_js_window(f, tool_label, start, window_lines))
        return out

    def _check_js_window(
        self, f: SourceFile, tool_label: str, start_line: int, window_lines: list[str]
    ) -> list[Finding]:
        out: list[Finding] = []
        for offset, raw_line in enumerate(window_lines):
            if js_util.is_comment_line(raw_line):
                continue
            lineno = start_line + offset
            code = js_util.code_part(raw_line)

            if _JS_RETURN_ENV.search(code):
                out.append(self._f(
                    "process.env returned wholesale from a tool response",
                    Severity.P0, Confidence.HIGH, f, lineno,
                    f"Tool '{tool_label}' returns `process.env` (or wraps it) "
                    "directly in its response -- every environment variable, "
                    "including any credential, is sent back to the calling LLM.",
                    "Never return the environment object. Return only the "
                    "specific, named, non-secret fields the tool actually needs "
                    "to report.",
                ))
                continue

            mw = _JS_RETURN_WHOLE_OBJECT_NAME.search(code)
            if mw:
                out.append(self._f(
                    "Whole config/settings object returned from a tool response",
                    Severity.P1, Confidence.MEDIUM, f, lineno,
                    f"Tool '{tool_label}' returns `{mw.group(1)}` directly -- if "
                    "this is a config/settings object it likely carries "
                    "credential fields straight back to the calling LLM.",
                    "Return an explicit allowlist of non-secret fields instead "
                    "of the whole config/settings object.",
                ))
                continue

            mb = _JS_BARE_RETURN_NAME.search(code)
            if mb and _name_looks_secret(mb.group(1)):
                out.append(self._secret_name_finding_js(f, tool_label, lineno, mb.group(1)))

        for offset, key, value in self._js_return_object_keys(window_lines):
            lineno = start_line + offset
            # Independent checks (matches the Python path's two separate
            # passes -- leaf-value shape and dict-key name) so a field like
            # `token: 'ghp_...'` is flagged on both signals, not just one.
            if _name_looks_secret(key):
                out.append(self._secret_name_finding_js(f, tool_label, lineno, key, via_key=True))
            for pat, what in _SECRET_VALUE_PATTERNS:
                if pat.search(value):
                    out.append(self._f(
                        f"Hardcoded {what} returned from a tool response",
                        Severity.P0, Confidence.HIGH, f, lineno,
                        f"Tool '{tool_label}' returns a literal that matches the "
                        f"shape of a {what}.",
                        "Never return a literal secret value; source it "
                        "server-side only, never echo it back through the "
                        "protocol.",
                    ))
        return out

    @staticmethod
    def _js_return_object_keys(window_lines: list[str]) -> list[tuple[int, str, str]]:
        """(offset, key, value-text) for keys inside a `return { ... }` block.

        Line-based brace-depth tracking, not a real parser: activates on a
        line matching `return {`, tracks net brace depth per line, and stops
        once depth returns to zero. Good enough for the common one-field-
        per-line object-literal style. Brace counting strips string-literal
        contents first (P1b fix) so a stray '}' inside a string VALUE
        (e.g. `note: "status is ok }"`) can't fool the depth tracker into
        closing the window before a later field is reached -- the depth
        count and the key/value extraction below deliberately use different
        text: braces are counted on the string-stripped copy, but the key
        and value themselves are still read from the original line so a
        real value like `apiKey: "sk-..."` isn't corrupted."""
        out: list[tuple[int, str, str]] = []
        depth = 0
        active = False
        for i, raw_line in enumerate(window_lines):
            if js_util.is_comment_line(raw_line):
                continue
            line = js_util.code_part(raw_line)
            brace_only = _JS_STRING_LITERAL.sub("", line)
            if not active:
                if re.search(r"\breturn\s*\{", brace_only):
                    active = True
                    depth = brace_only.count("{") - brace_only.count("}")
                    if depth <= 0:
                        active = False
                continue
            depth += brace_only.count("{") - brace_only.count("}")
            km = _JS_OBJECT_KEY.match(line)
            if km:
                out.append((i, km.group(1), km.group(2).strip()))
            if depth <= 0:
                active = False
        return out

    def _secret_name_finding_js(
        self, f: SourceFile, tool_label: str, lineno: int, name: str, via_key: bool = False
    ) -> Finding:
        where = f"a response field named '{name}'" if via_key else f"'{name}'"
        return self._f(
            "Secret-named value returned from a tool response",
            Severity.P1, Confidence.MEDIUM, f, lineno,
            f"Tool '{tool_label}' returns {where}, whose name matches the "
            "secret-name heuristic (secret/token/password/api-key/"
            "private-key/client-secret) -- the calling LLM receives it "
            "verbatim in the tool's response.",
            "Never return a credential in a tool's response payload. Return "
            "a boolean 'present/absent' or a fixed redaction mask instead.",
        )

    def _check_return(self, f: SourceFile, fn: ast.AST, ret: ast.Return) -> list[Finding]:
        out: list[Finding] = []
        expr = ret.value
        leaves = _leaf_values(expr)
        keys = _dict_keys(expr)

        for leaf in leaves:
            # os.environ (or a call wrapping it) returned wholesale
            if isinstance(leaf, ast.Attribute) and _dotted(leaf) == "os.environ":
                out.append(self._f(
                    "os.environ returned wholesale from a tool response",
                    Severity.P0, Confidence.HIGH, f, ret.lineno,
                    f"Tool '{fn.name}' returns `os.environ` (or wraps it) directly in "
                    "its response — every environment variable, including any "
                    "credential, is sent back to the calling LLM.",
                    "Never return the environment object. Return only the specific, "
                    "named, non-secret fields the tool actually needs to report.",
                ))
                continue
            if isinstance(leaf, ast.Call):
                cname = _dotted(leaf.func)
                cshort = cname.split(".")[-1] if cname else ""
                if cshort in ("vars", "asdict") and leaf.args:
                    arg_name = _dotted(leaf.args[0]).split(".")[-1] or "object"
                    out.append(self._f(
                        "Whole config/settings object dumped into a tool response",
                        Severity.P1, Confidence.MEDIUM, f, ret.lineno,
                        f"Tool '{fn.name}' returns `{cshort}({arg_name})` — every "
                        "attribute of that object, including any credential field, "
                        "is serialized straight into the tool's response.",
                        "Return an explicit allowlist of non-secret fields instead "
                        "of dumping the whole object.",
                    ))
                    continue
            if isinstance(leaf, ast.Attribute) and leaf.attr == "__dict__":
                out.append(self._f(
                    "Whole object __dict__ dumped into a tool response",
                    Severity.P1, Confidence.MEDIUM, f, ret.lineno,
                    f"Tool '{fn.name}' returns `{_dotted(leaf)}` — every attribute of "
                    "that object, including any credential field, is serialized "
                    "straight into the tool's response.",
                    "Return an explicit allowlist of non-secret fields instead of "
                    "dumping `__dict__`.",
                ))
                continue
            if isinstance(leaf, ast.Name) and leaf.id.lower() in _WHOLE_OBJECT_NAME:
                out.append(self._f(
                    "Whole config/settings object returned from a tool response",
                    Severity.P1, Confidence.MEDIUM, f, ret.lineno,
                    f"Tool '{fn.name}' returns `{leaf.id}` directly — if this is a "
                    "config/settings object it likely carries credential fields "
                    "straight back to the calling LLM.",
                    "Return an explicit allowlist of non-secret fields instead of the "
                    "whole config/settings object.",
                ))
                continue
            if isinstance(leaf, ast.Name) and _name_looks_secret(leaf.id):
                out.append(self._secret_name_finding(f, fn, ret, leaf.id))
            elif isinstance(leaf, ast.Attribute) and _name_looks_secret(leaf.attr):
                out.append(self._secret_name_finding(f, fn, ret, _dotted(leaf)))
            elif isinstance(leaf, ast.Constant) and isinstance(leaf.value, str):
                for pat, what in _SECRET_VALUE_PATTERNS:
                    if pat.search(leaf.value):
                        out.append(self._f(
                            f"Hardcoded {what} returned from a tool response",
                            Severity.P0, Confidence.HIGH, f, ret.lineno,
                            f"Tool '{fn.name}' returns a literal that matches the shape "
                            f"of a {what}.",
                            "Never return a literal secret value; source it server-side "
                            "only, never echo it back through the protocol.",
                        ))

        # dict keys that are themselves secret-named, regardless of the
        # corresponding value's own name (the field label alone is the leak
        # signal a calling LLM sees).
        for key in keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and _name_looks_secret(key.value):
                out.append(self._secret_name_finding(f, fn, ret, key.value, via_key=True))
        return out

    def _secret_name_finding(self, f: SourceFile, fn: ast.AST, ret: ast.Return, name: str, via_key: bool = False) -> Finding:
        where = f"a response field named '{name}'" if via_key else f"'{name}'"
        return self._f(
            "Secret-named value returned from a tool response",
            Severity.P1, Confidence.MEDIUM, f, ret.lineno,
            f"Tool '{fn.name}' returns {where}, whose name matches the secret-name "
            "heuristic (secret/token/password/api-key/private-key/client-secret) — "
            "the calling LLM receives it verbatim in the tool's response.",
            "Never return a credential in a tool's response payload. Return a "
            "boolean 'present/absent' or a fixed redaction mask instead.",
        )

    def _f(self, title, sev, conf, f: SourceFile, line, detail, remediation) -> Finding:
        return Finding(
            vuln_class=self.name, title=title, severity=sev, confidence=conf,
            file=f.rel, line=line, detail=detail, remediation=remediation,
            snippet=f.line_at(line),
        )
