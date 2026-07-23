"""Detector 6 — secret-leak-via-tool-response.

``secret_handling.py`` only checks secrets at rest (tracked files, hardcoded
literals) and secrets passed to ``print``/``log.*``. It never inspects what a
tool handler actually hands back to the *calling LLM* through the MCP
protocol — a distinct leak surface: a tool can be perfectly fine about not
logging a credential and still return it verbatim in its response payload.

This detector walks every ``@mcp.tool()``/``@server.tool()``-decorated
function's ``return`` expression(s), AND (2026-07-23) every low-level MCP SDK
``@server.call_tool()`` dispatch handler's returns -- both its own top-level
returns and the returns of a helper function it plainly delegates to (one
hop, same convention as ``tool_scope_creep.py``'s helper-delegation hop) --
and flags a leak-shaped value when the returned dict/tuple/list/bare-expression
includes, at a leaf value position:

* ``os.environ`` itself (the whole environment dumped back to the caller);
* a whole config/settings object returned wholesale (``return config``,
  ``vars(config)``, ``config.__dict__``, ``dataclasses.asdict(config)``);
* a variable/attribute whose name matches the secret-name heuristic, or a
  dict key literal that does;
* a hardcoded secret-shaped string literal (reuses ``secret_handling.py``'s
  own value-pattern list directly).

Reuse, not reinvention: the secret-name vocabulary is the exact
``_SECRET_NAME`` regex object, and the word-boundary-aware wrapper around it
(``_name_looks_secret``) that rejects a match glued to more letters on
either side with no separator between them (e.g. ``tokenizer_version``,
``passwordless_mode``, ``apiKeyValidator`` — a *glued* substring, not a real
secret; ``SECRET_KEY``/``api_key`` still fire), are both imported from
``secret_handling.py`` (moved there 2026-07-22 so ``secret_handling.py``'s
own JS-logging check could reuse the same guard instead of carrying a second,
weaker copy — see that module for the implementation).

Low-level MCP SDK coverage (2026-07-23): this file used to carry its OWN
private copy of ``_is_tool_decorator`` and never looked at a low-level SDK
``@server.call_tool()`` dispatch handler at all, so a repo using ONLY that
shape (no ``@mcp.tool()`` decorators anywhere) got zero coverage from this
detector regardless of what its tool responses leaked. Fixed by importing
the decorator/provenance helpers from ``tool_registry.py`` (one parser, not
two) and adding ``_scan_low_level_sdk``: for each file gated on
``_file_imports_mcp`` with exactly one ``@server.call_tool()`` handler (zero
or ambiguous -> skip, never guess a root — same as ``_extract_low_level_sdk``),
``tool_registry.dispatch_segments`` splits the handler body into per-tool
branches; each branch's own returns AND the returns of a one-hop delegated
helper are inspected. A branch attributable to one specific literal tool
name (``if name == "x":``) is labeled with that tool; anything else (an
``in (...)`` branch, the final ``else``, code outside the if/elif chain, or
no if/elif dispatch shape at all) is labeled as the dispatch handler itself
— never a guessed tool name. Known boundary, disclosed rather than silently
left: only a literal ``==`` if/elif walk is recognized as attributable
dispatch; a dict-keyed dispatch table or ``match``/``case`` statement falls
back to whole-handler attribution (see ``tool_registry.dispatch_segments``).
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .. import js_util
from ..tool_registry import (
    extract_tool_registry,
    _is_tool_decorator,
    _is_call_tool_decorator,
    _file_imports_mcp,
    _decorated_in_file,
    dispatch_segments,
)
from .base import Detector, RepoContext, SourceFile
from .secret_handling import _SECRET_VALUE_PATTERNS, _JS_STRING_LITERAL, _name_looks_secret

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

# P2-honesty fix: a compressed one-line object literal (`return {a: 1};`)
# opens and closes its brace on the same physical line -- the multi-line
# brace-depth state machine below only ever inspects the FOLLOWING lines for
# keys, so this shape was silently never decomposed (0 findings) despite an
# inline comment previously (and falsely) claiming it was already covered.
_JS_SAME_LINE_RETURN_OBJECT = re.compile(r"\breturn\s*\{(.*)\}\s*;?\s*$")
_JS_FIELD_KEY = re.compile(r"^[\"']?([A-Za-z_$][A-Za-z0-9_$]*)[\"']?\s*:\s*(.+)$", re.DOTALL)


def _split_top_level_commas(s: str) -> list[str]:
    """Split ``s`` on commas that are not inside a nested (), [], {} or a
    string/template literal -- so a nested object/array value or a comma
    inside a string doesn't get cut mid-field."""
    parts: list[str] = []
    depth = 0
    start = 0
    in_str: str | None = None
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in "'\"`":
            in_str = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(s[start:i])
            start = i + 1
        i += 1
    parts.append(s[start:])
    return parts


def _same_line_return_fields(line: str) -> list[tuple[str, str]]:
    """(key, value-text) pairs for a `return { ... };` object literal that
    opens and closes entirely on one line."""
    m = _JS_SAME_LINE_RETURN_OBJECT.search(line)
    if not m:
        return []
    out: list[tuple[str, str]] = []
    for part in _split_top_level_commas(m.group(1)):
        part = part.strip()
        if not part:
            continue
        km = _JS_FIELD_KEY.match(part)
        if km:
            out.append((km.group(1), km.group(2).strip()))
    return out


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


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


def _stmts_direct_returns(stmts: list[ast.stmt]):
    """Same skip-nested-def/lambda rule as ``_direct_returns``, but starting
    from a list of statements (a ``dispatch_segments`` branch body) rather
    than a single function node."""
    for stmt in stmts:
        if isinstance(stmt, ast.Return):
            yield stmt
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        else:
            yield from _direct_returns(stmt)


def _file_function_index(f: SourceFile) -> dict[str, list[ast.AST]]:
    """name -> [FunctionDef/AsyncFunctionDef, ...] within this ONE file
    only. 2026-07-23 P0-2 N-vote fix: the previous cut built this repo-wide
    by short name, so an unrelated, never-imported same-named helper
    elsewhere in the repo (e.g. a debug script's own ``_format`` that dumps
    ``os.environ``) could be resolved as the one-hop target for a call in a
    completely different, clean file -- fabricating a P0 leak finding
    against a tool that never touches it. Same-file-only matches the
    same-file-only ``Tool()``<->dispatcher correlation precedent already
    shipped in ``_extract_low_level_sdk`` -- a helper in another file that
    isn't provably reachable this way is an honest miss, disclosed, not a
    guessed hit."""
    idx: dict[str, list[ast.AST]] = {}
    if f.tree is None:
        return idx
    for node in ast.walk(f.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            idx.setdefault(node.name, []).append(node)
    return idx


def _one_hop_dispatched_funcs(
    stmts: list[ast.stmt], file_func_index: dict[str, list[ast.AST]], exclude: ast.AST
) -> list[ast.AST]:
    """Every helper function this branch/segment plainly calls by name,
    resolved one hop via ``file_func_index`` -- SAME FILE ONLY (see
    ``_file_function_index``). No proof the call's return value is
    literally what gets returned upstream, same over-flag-rather-than-miss
    convention as ``tool_scope_creep.py``'s one-hop helper resolution."""
    out: list[ast.AST] = []
    seen: set[int] = set()
    for stmt in stmts:
        for sub in ast.walk(stmt):
            if not isinstance(sub, ast.Call):
                continue
            dotted = _dotted(sub.func)
            short = dotted.split(".")[-1] if dotted else ""
            if not short or short not in file_func_index:
                continue
            for cnode in file_func_index[short]:
                if cnode is exclude or id(cnode) in seen:
                    continue
                seen.add(id(cnode))
                out.append(cnode)
    return out


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
                    findings.extend(self._check_return(f, f"Tool '{node.name}'", ret))
            if _file_imports_mcp(f):
                findings.extend(self._scan_low_level_sdk(f))
        findings.extend(self._scan_js(ctx))
        return findings

    # --- low-level MCP SDK: call_tool dispatch handler --------------------
    def _scan_low_level_sdk(self, f: SourceFile) -> list[Finding]:
        handlers = _decorated_in_file(f, _is_call_tool_decorator)
        if len(handlers) != 1:
            # Zero, or more than one, call_tool handler in this file --
            # never guess a root (mirrors _extract_low_level_sdk).
            return []
        handler = handlers[0]
        handler_label = f"the '{handler.name}' dispatch handler"
        file_func_index = _file_function_index(f)

        out: list[Finding] = []
        for tool_name, stmts, _shared in dispatch_segments(handler):
            label = f"Tool '{tool_name}'" if tool_name else handler_label
            for ret in _stmts_direct_returns(stmts):
                if ret.value is None:
                    continue
                out.extend(self._check_return(f, label, ret))
            for cnode in _one_hop_dispatched_funcs(stmts, file_func_index, handler):
                for ret in _direct_returns(cnode):
                    if ret.value is None:
                        continue
                    out.extend(self._check_return(f, label, ret))
        return out

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
        real value like `apiKey: "sk-..."` isn't corrupted.

        A compressed one-line object literal (`return {a: 1, b: 2};`, opens
        and closes its brace on the same physical line) is decomposed via
        `_same_line_return_fields` instead of entering the multi-line state
        machine (P2-honesty fix, 2026-07-22): a prior version of this
        docstring claimed the whole-object/process.env checks elsewhere in
        this file already covered this shape -- they don't (neither matches
        a compound object literal), so it was silently 0 findings."""
        out: list[tuple[int, str, str]] = []
        depth = 0
        active = False
        for i, raw_line in enumerate(window_lines):
            if js_util.is_comment_line(raw_line):
                continue
            line = js_util.code_part(raw_line)
            if not active:
                same_line = _same_line_return_fields(line)
                if same_line:
                    out.extend((i, k, v) for k, v in same_line)
                    continue
                brace_only = _JS_STRING_LITERAL.sub("", line)
                if re.search(r"\breturn\s*\{", brace_only):
                    active = True
                    depth = brace_only.count("{") - brace_only.count("}")
                    if depth <= 0:
                        active = False
                continue
            brace_only = _JS_STRING_LITERAL.sub("", line)
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

    def _check_return(self, f: SourceFile, label: str, ret: ast.Return) -> list[Finding]:
        """``label`` is a pre-formatted subject phrase for the finding
        message -- ``"Tool 'x'"`` for a decorator-registered tool or an
        unambiguous low-level-SDK dispatch branch, or a dispatch-handler
        description (e.g. ``"the 'call_tool' dispatch handler"``) when
        attribution to one specific tool isn't possible (never guessed)."""
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
                    f"{label} returns `os.environ` (or wraps it) directly in "
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
                        f"{label} returns `{cshort}({arg_name})` — every "
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
                    f"{label} returns `{_dotted(leaf)}` — every attribute of "
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
                    f"{label} returns `{leaf.id}` directly — if this is a "
                    "config/settings object it likely carries credential fields "
                    "straight back to the calling LLM.",
                    "Return an explicit allowlist of non-secret fields instead of the "
                    "whole config/settings object.",
                ))
                continue
            if isinstance(leaf, ast.Name) and _name_looks_secret(leaf.id):
                out.append(self._secret_name_finding(f, label, ret, leaf.id))
            elif isinstance(leaf, ast.Attribute) and _name_looks_secret(leaf.attr):
                out.append(self._secret_name_finding(f, label, ret, _dotted(leaf)))
            elif isinstance(leaf, ast.Constant) and isinstance(leaf.value, str):
                for pat, what in _SECRET_VALUE_PATTERNS:
                    if pat.search(leaf.value):
                        out.append(self._f(
                            f"Hardcoded {what} returned from a tool response",
                            Severity.P0, Confidence.HIGH, f, ret.lineno,
                            f"{label} returns a literal that matches the shape "
                            f"of a {what}.",
                            "Never return a literal secret value; source it server-side "
                            "only, never echo it back through the protocol.",
                        ))

        # dict keys that are themselves secret-named, regardless of the
        # corresponding value's own name (the field label alone is the leak
        # signal a calling LLM sees).
        for key in keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and _name_looks_secret(key.value):
                out.append(self._secret_name_finding(f, label, ret, key.value, via_key=True))
        return out

    def _secret_name_finding(self, f: SourceFile, label: str, ret: ast.Return, name: str, via_key: bool = False) -> Finding:
        where = f"a response field named '{name}'" if via_key else f"'{name}'"
        return self._f(
            "Secret-named value returned from a tool response",
            Severity.P1, Confidence.MEDIUM, f, ret.lineno,
            f"{label} returns {where}, whose name matches the secret-name "
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
