"""Detector 2 — tool-parameter injection surfaces.

Sinks that turn a tool argument into code / a shell / an arbitrary file / an
arbitrary URL:

* ``subprocess.*(..., shell=True)`` and ``os.system`` / ``os.popen``
* ``eval`` / ``exec`` on a non-constant
* ``pickle.load`` / ``pickle.loads``
* ``yaml.load`` without a safe loader
* file ops (``open`` etc.) on a variable path in a repo with no path-containment
  primitive present  -> possible traversal (low confidence)
* HTTP fetch (``requests`` / ``httpx`` / ``urllib.urlopen``) of a non-constant
  URL with no allowlist present  -> possible SSRF (medium confidence)

All AST-based to keep the false-positive rate low.
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .. import js_util
from .base import Detector, RepoContext, SourceFile

_CONTAINMENT_HINTS = (
    "realpath", "resolve", "commonpath", "commonprefix", "is_relative_to",
    "relative_to", "abspath", "safe_join", "secure_filename",
)
_ALLOWLIST_HINTS = (
    "allowlist", "allow_list", "whitelist", "ALLOWED", "allowed_hosts",
    "allowed_domains", "urlparse", "hostname", "netloc",
)

# --- JS/TS parity sinks --------------------------------------------------
# Regex/line-based (see js_util's honesty note) -- there is no JS/TS AST in
# this scanner. Mirrors the same sink classes the Python AST pass checks:
# shell-injection, code-eval, unsafe-deserialization, ssrf, path-traversal.
_JS_CHILD_PROCESS_IMPORT = re.compile(
    r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]"""
)
_JS_SPAWN_EXECFILE_CALL = re.compile(r"\b(?:child_process\.)?(?:spawn|execFile)(?:Sync)?\s*\(")

# --- Wave-1 FP fix: RegExp.prototype.exec() vs child_process.exec() ------
# The original exec-call regex matched bare "exec(Sync)?(" regardless of
# what came before it -- so `myRegex.exec(str)` (a RegExp match call) was
# indistinguishable from `child_process.exec(cmd)` whenever the SAME FILE
# also imported child_process for a real, legitimate use elsewhere (e.g. an
# execSync call two functions away). Fixed structurally: resolve the call's
# receiver and demote only when it confidently names a RegExp value.
_JS_EXEC_RECEIVER = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*exec(?:Sync)?\s*\(")
_JS_BARE_EXEC = re.compile(r"(?<![\w$.])exec(?:Sync)?\s*\(")
_JS_REGEX_LITERAL_EXEC = re.compile(
    r"""(?<![\w$])/(?:\\.|[^/\\\r\n])+/[a-zA-Z]*\s*\.\s*exec(?:Sync)?\s*\("""
)
# Same-file, bounded resolution (mirrors _js_child_process_aliases' own
# same-file convention): a variable assigned `new RegExp(...)` or a
# `/pattern/flags` literal is a confidently-resolved RegExp receiver.
_JS_REGEX_VAR_NEW = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+RegExp\s*\("
)
_JS_REGEX_VAR_LITERAL = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/(?:\\.|[^/\\\r\n])+/[a-zA-Z]*\s*(?:;|,|\)|$)"""
)


# --- Round-2 N-vote P0-2 fix: brace-scoped RegExp receiver resolution -----
# (Superseded the wave-1 file-wide `_js_regexp_var_names` set two refuters
# proved live: a RegExp var declared in one function silently demoted an
# unrelated child_process.exec() sink of the same name in a completely
# different function. Removed outright, not kept as a dead alias.)
# A RegExp-var assignment is only a valid resolution for a `.exec(` call at
# line L when L falls within that assignment's own innermost enclosing
# {...} block (real JS block-scoping for const/let) -- or when the
# assignment has NO enclosing block at all (module/top-level scope, which
# real closures make visible from any nested function). This is a text-only
# approximation of a real scope walk (no JS/TS AST in this scanner, see the
# module docstring's honesty note), built the same way the rest of this
# file's other JS heuristics are: bounded, same-file, over-flag-safe on
# anything it can't resolve.
_JS_CP_MODULE_BINDING = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)"""
    r"""|import\s+([A-Za-z_$][\w$]*)\s+from\s+['"](?:node:)?child_process['"]"""
    r"""|import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"](?:node:)?child_process['"]"""
)


_JS_REGEX_CONTEXT_PRECEDING = set("([{,;:=!&|?+-*%^~<>")
# Round-3 N-vote P0-C fix: a `/` immediately after one of these KEYWORDS
# is also a regex-literal context, not just after a symbol -- the
# original heuristic only checked the last SIGNIFICANT CHARACTER, so
# `return /^{$/.test(x)` (last char of "return" is alnum, not a symbol)
# was never recognized as a regex opener at all. Its embedded `{`/`}`
# then leaked into the brace-based scope walk as if they were real code
# braces, corrupting (merging/mis-splitting) function-scope spans --
# live repro (shadow6): two such literals in one file merged spans and
# masked a real child_process.exec() sink elsewhere in the same file
# (0 findings). List mirrors common real-world JS-linter regex-context
# keyword sets.
_JS_REGEX_CONTEXT_KEYWORDS = {
    "return", "typeof", "case", "in", "of", "delete", "void", "do",
    "else", "yield", "await", "instanceof", "new", "throw",
}
_JS_WORD_CHAR = re.compile(r"[A-Za-z0-9_$]")


def _strip_js_noise(text: str) -> str:
    """Blank out string/template-literal, comment, and regex-literal BODY
    contents (same length, newlines preserved) so brace-counting for scope
    extraction isn't confused by braces appearing inside any of them --
    notably a Unicode property escape (``/\\p{Cf}/``) or a quantifier
    (``/x{2,4}/``) inside a regex literal, both containing literal `{`/`}`
    that corrupted scope extraction before this fix (round-2 N-vote P0-2,
    live repro: ``const cfPattern = /\\p{Cf}/gu;`` produced a spurious
    single-line "scope" from the regex body's own braces, breaking the
    enclosing function's real span).

    Regex-vs-division is genuinely ambiguous without a real parser; this
    uses the same preceding-token heuristic real-world JS linters use: a
    `/` opens a regex literal when the last significant (non-whitespace,
    non-blanked) character before it is one of ``([{,;:=!&|?+-*%^~<>``,
    there is no such character yet (start of file/statement), OR (round-3
    N-vote P0-C fix) the last COMPLETE WORD token was a regex-context
    keyword (``return``, ``typeof``, ``case``, ``in``, ``of``, ``delete``,
    ``void``, ``do``, ``else``, ``yield``, ``await``, ``instanceof``,
    ``new``, ``throw``) -- a keyword ends in an alphanumeric character, so
    the symbol-only check alone could never recognize it. An ambiguous or
    unterminated `/` is left alone (treated as division) -- the safe
    direction: worse case is an unstripped regex body that could still
    miscount a brace, which is now caught by the fail-closed balance check
    in ``_js_block_spans_by_line`` rather than silently corrupting scope
    info, no different from the pre-fix behavior for that narrow shape."""
    out: list[str] = []
    i, n = 0, len(text)
    last_sig = ""
    last_word = ""
    word_buf: list[str] = []

    def _flush_word():
        nonlocal last_word
        if word_buf:
            last_word = "".join(word_buf).lower()
            word_buf.clear()

    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            _flush_word()
            j = i
            while j < n and text[j] not in "\r\n":
                j += 1
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            _flush_word()
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(ch if ch in "\r\n" else " " for ch in text[i:j]))
            i = j
            last_sig = " "
            continue
        if c in ("'", '"', "`"):
            _flush_word()
            quote = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            out.append("".join(ch if ch in "\r\n" else " " for ch in text[i:j]))
            i = j
            last_sig = '"'
            continue
        if c == "/" and (
            last_sig == ""
            or last_sig in _JS_REGEX_CONTEXT_PRECEDING
            or (last_sig.isalnum() and last_word in _JS_REGEX_CONTEXT_KEYWORDS)
        ):
            j = i + 1
            terminated = False
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] in "\r\n":
                    break
                if text[j] == "/":
                    terminated = True
                    j += 1
                    break
                j += 1
            if terminated:
                while j < n and text[j].isalpha():
                    j += 1
                seg = text[i:j]
                out.append("".join(ch if ch in "\r\n" else " " for ch in seg))
                i = j
                last_sig = "/"
                last_word = ""
                continue
            # Unterminated on this line -- not actually a regex literal;
            # fall through and treat this `/` as an ordinary character.
        out.append(c)
        if _JS_WORD_CHAR.match(c):
            word_buf.append(c)
        else:
            _flush_word()
        if not c.isspace():
            last_sig = c
        i += 1
    return "".join(out)


def _js_block_spans_by_line(text: str) -> list[tuple[int, int]] | None:
    """(start_line, end_line), 1-indexed inclusive, for every ``{...}``
    block found via brace-depth matching over noise-stripped text (see
    ``_strip_js_noise``). Nested blocks each get their own span; spans are
    otherwise either disjoint or fully nested (a property of matched
    braces), which is what makes the innermost-span lookup below correct.

    Round-3 N-vote P0-C fix: FAILS CLOSED. If the braces in this file
    don't balance (an unmatched ``{`` left open at EOF, or a stray ``}``
    with nothing to close -- whether from genuinely malformed/truncated
    source or a regex-literal shape ``_strip_js_noise``'s heuristic still
    doesn't recognize), this returns ``None`` (a DISTINCT sentinel from
    the empty list, which means "no braces at all, but reliable") rather
    than a partial, possibly-corrupted span set. The caller
    (``_js_bindings_by_scope``) treats ``None`` as "discard every binding
    in this file" -- NOT "everything is module-scope visible", which
    would be the wrong direction (it would make a same-named receiver
    resolve as a RegExp match MORE often, masking a real sink instead of
    over-flagging it). Every ``.exec(`` receiver then resolves to
    "unknown" and stays flagged -- over-flag-safe parity, matching the
    file-wide (pre-scope) fix's behavior, rather than trusting a scope
    tree that might be silently wrong in a way that masks a real sink."""
    clean = _strip_js_noise(text)
    stack: list[int] = []
    spans: list[tuple[int, int]] = []
    stray_close = False
    for idx, ch in enumerate(clean):
        if ch == "{":
            stack.append(idx)
        elif ch == "}":
            if stack:
                start = stack.pop()
                spans.append((clean.count("\n", 0, start) + 1, clean.count("\n", 0, idx) + 1))
            else:
                stray_close = True
    if stack or stray_close:
        return None
    return spans


def _innermost_span_containing(spans: list[tuple[int, int]], line: int) -> tuple[int, int] | None:
    best: tuple[int, int] | None = None
    for s, e in spans:
        if s <= line <= e and (best is None or (e - s) < (best[1] - best[0])):
            best = (s, e)
    return best


_JS_HUGE_LINE = 10**9  # sentinel "end of file" for a module-scope binding


def _js_bindings_by_scope(text: str) -> list[tuple[str, str, int, int]]:
    """[(name, kind, scope_start_line, scope_end_line)] for EVERY
    RegExp-var assignment (kind="regexp") AND EVERY direct child_process
    MODULE-object binding (kind="cp_module") in the file, each scoped to
    its own innermost enclosing block (or module scope, (1, _JS_HUGE_LINE),
    when declared at top level).

    Both kinds share one scope-resolution pass so shadowing resolves
    correctly: a name can legitimately be declared as BOTH a RegExp in one
    function AND a child_process reference in a different function (or at
    module scope) -- ``_resolve_receiver_kind`` below picks whichever
    declaration's scope is the SMALLEST (innermost/most specific) one that
    contains the usage line, exactly like real JS block-scoping resolves a
    shadowed identifier. Computing this jointly (not as two independent
    "is this name ever a regexp" / "is this name ever a cp module" sets) is
    what stops a local RegExp shadow in one function from leaking into an
    unrelated function's real child_process usage of the same name, and
    the reverse.

    Round-3 N-vote P0-C fix: if ``_js_block_spans_by_line`` returns
    ``None`` (brace imbalance detected -- unreliable), this returns an
    EMPTY bindings list outright, discarding every RegExp/cp_module
    binding in the file rather than treating them as module-scope-visible
    (which would be the wrong, mask-a-real-sink direction)."""
    spans = _js_block_spans_by_line(text)
    if spans is None:
        return []
    out: list[tuple[str, str, int, int]] = []
    for pat, kind in (
        (_JS_REGEX_VAR_NEW, "regexp"),
        (_JS_REGEX_VAR_LITERAL, "regexp"),
        (_JS_CP_MODULE_BINDING, "cp_module"),
    ):
        for m in pat.finditer(text):
            name = next((g for g in m.groups() if g), None)
            if not name:
                continue
            decl_line = text.count("\n", 0, m.start()) + 1
            enclosing = _innermost_span_containing(spans, decl_line)
            if enclosing is None:
                out.append((name, kind, 1, _JS_HUGE_LINE))
            else:
                out.append((name, kind, enclosing[0], enclosing[1]))
    return out


def _resolve_receiver_kind(
    bindings: list[tuple[str, str, int, int]], name: str, lineno: int
) -> str | None:
    """Among every recorded binding of ``name`` whose scope contains
    ``lineno``, return the kind of the SMALLEST (innermost/most specific)
    one -- the real-JS-shadowing-correct resolution -- or ``None`` if no
    binding of this name is visible at this line at all (unresolved).
    Ties (same scope size, contradictory kinds -- not valid real JS, but
    defensive) resolve to "cp_module" (the safe, still-flagged direction)."""
    best_size: int | None = None
    best_kind: str | None = None
    for bname, kind, start, end in bindings:
        if bname != name or not (start <= lineno <= end):
            continue
        size = end - start
        if best_size is None or size < best_size:
            best_size, best_kind = size, kind
        elif size == best_size and kind == "cp_module":
            best_kind = "cp_module"
    return best_kind

# --- P1d: destructure-aliased child_process bindings ---------------------
# `const { exec: run } = require('child_process')` (require form) or
# `import { exec as run } from 'child_process'` (import form) rebinds the
# sink under a name the fixed regexes above never see -- calls to the alias
# (`run(...)`) were a total blind spot. Parsed separately per-file and the
# alias names folded into the same exec / spawn-execFile sink checks.
_JS_CP_DESTRUCTURE_REQUIRE = re.compile(
    r"""\{([^}]*)\}\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)"""
)
_JS_CP_DESTRUCTURE_IMPORT = re.compile(
    r"""import\s*\{([^}]*)\}\s*from\s*['"](?:node:)?child_process['"]"""
)
_JS_CP_BINDING_ITEM = re.compile(
    r"^([A-Za-z_$][\w$]*)\s*(?::|as)\s*([A-Za-z_$][\w$]*)$|^([A-Za-z_$][\w$]*)$"
)
_EXEC_BIND_NAMES = {"exec", "execSync"}
_SPAWN_EXECFILE_BIND_NAMES = {"spawn", "execFile", "spawnSync", "execFileSync"}


def _js_child_process_aliases(text: str) -> tuple[set[str], set[str]]:
    """Return (exec_aliases, spawn_execfile_aliases) bound via a
    destructured child_process require/import, including any `: alias`
    (require) / `as alias` (import) rename. Plain (non-aliased) bindings
    fold back to their own name, so this also covers the un-renamed case
    uniformly with the regex-literal checks above."""
    exec_names: set[str] = set()
    spawn_names: set[str] = set()

    def _consume(members: str) -> None:
        for item in members.split(","):
            item = item.strip()
            if not item:
                continue
            m = _JS_CP_BINDING_ITEM.match(item)
            if not m:
                continue
            if m.group(3):
                orig = alias = m.group(3)
            else:
                orig, alias = m.group(1), m.group(2)
            if orig in _EXEC_BIND_NAMES:
                exec_names.add(alias)
            elif orig in _SPAWN_EXECFILE_BIND_NAMES:
                spawn_names.add(alias)

    for m in _JS_CP_DESTRUCTURE_REQUIRE.finditer(text):
        _consume(m.group(1))
    for m in _JS_CP_DESTRUCTURE_IMPORT.finditer(text):
        _consume(m.group(1))
    return exec_names, spawn_names


def _js_alias_call(line: str, names: set[str]) -> bool:
    if not names:
        return False
    pat = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\s*\(")
    return bool(pat.search(line))
_JS_SHELL_TRUE = re.compile(r"shell\s*:\s*true", re.IGNORECASE)
_JS_EVAL_CALL = re.compile(r"\beval\s*\(")
_JS_NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\(")
_JS_YAML_LOAD = re.compile(r"\byaml\.load\s*\(")
_JS_YAML_SAFE_SCHEMA = re.compile(r"JSON_SCHEMA|SAFE_SCHEMA|FAILSAFE_SCHEMA")
_JS_FETCH_CALL = re.compile(r"\bfetch\s*\(")
_JS_AXIOS_CALL = re.compile(r"\baxios\.(?:get|post|put|delete|patch|request)\s*\(")
_JS_HTTP_GET_CALL = re.compile(r"\b(?:http|https)\.get\s*\(")
_JS_FS_PATH_CALL = re.compile(
    r"\bfs\.(?:readFile|writeFile|appendFile|unlink)(?:Sync)?\s*\("
)


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for a call target."""
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_constant_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class ParamInjectionDetector(Detector):
    name = "param-injection"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        for f in ctx.files:
            if f.suffix in js_util.JS_SUFFIXES:
                findings.extend(self._scan_js(f))
                continue
            if f.tree is None:
                continue
            text = f.text
            has_containment = any(h in text for h in _CONTAINMENT_HINTS)
            has_allowlist = any(h in text for h in _ALLOWLIST_HINTS)
            for node in ast.walk(f.tree):
                if isinstance(node, ast.Call):
                    findings.extend(
                        self._check_call(node, f, has_containment, has_allowlist)
                    )
        return findings

    # --- JS/TS: line-based sink regex (no AST available) -----------------
    def _scan_js(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        text = f.text
        has_child_process = bool(_JS_CHILD_PROCESS_IMPORT.search(text))
        exec_aliases, spawn_aliases = _js_child_process_aliases(text)
        has_child_process = has_child_process or bool(exec_aliases) or bool(spawn_aliases)
        bindings = _js_bindings_by_scope(text)
        has_containment = any(h in text for h in _CONTAINMENT_HINTS)
        has_allowlist = any(h in text for h in _ALLOWLIST_HINTS)

        for i, raw_line in enumerate(f.lines, start=1):
            if js_util.is_comment_line(raw_line):
                continue
            line = js_util.code_part(raw_line)

            if has_child_process:
                if self._js_is_real_exec_call(line, i, exec_aliases, bindings):
                    out.append(self._f(
                        "shell-injection", "child_process.exec(Sync) invocation",
                        Severity.P1, Confidence.HIGH, f, i,
                        "child_process.exec/execSync always runs its command string "
                        "through a shell; any tool-controlled substring becomes shell "
                        "metacharacters.",
                        "Use execFile/spawn with an argv array (shell:false, the "
                        "default). If a shell is unavoidable, escape every "
                        "interpolated value and reject metacharacters.",
                    ))
                m = _JS_SPAWN_EXECFILE_CALL.search(line) or _js_alias_call(line, spawn_aliases)
                if m and _JS_SHELL_TRUE.search(line):
                    out.append(self._f(
                        "shell-injection", "spawn/execFile called with shell:true",
                        Severity.P1, Confidence.HIGH, f, i,
                        "spawn/execFile with shell:true runs its argument through a "
                        "shell; any tool-controlled substring becomes shell "
                        "metacharacters.",
                        "Drop shell:true and pass argv as a list.",
                    ))

            me = _JS_EVAL_CALL.search(line)
            if me:
                arg = js_util.first_call_arg(line, me.end() - 1)
                if not js_util.is_const_arg(arg):
                    out.append(self._f(
                        "code-eval", "eval() on a non-constant value",
                        Severity.P0, Confidence.HIGH, f, i,
                        "eval() executes arbitrary JavaScript from its argument.",
                        "Remove eval(). Parse structured input explicitly "
                        "(JSON.parse for JSON, a real parser otherwise).",
                    ))

            if _JS_NEW_FUNCTION.search(line):
                out.append(self._f(
                    "code-eval", "new Function(...) constructs code from its argument",
                    Severity.P0, Confidence.HIGH, f, i,
                    "The Function constructor compiles its string argument as "
                    "JavaScript -- the same class of risk as eval().",
                    "Remove the dynamic Function constructor; parse structured "
                    "input explicitly instead of compiling code from it.",
                ))

            my = _JS_YAML_LOAD.search(line)
            if my and not _JS_YAML_SAFE_SCHEMA.search(line):
                out.append(self._f(
                    "unsafe-deserialization", "yaml.load without a safe schema",
                    Severity.P1, Confidence.MEDIUM, f, i,
                    "js-yaml's yaml.load with the default schema can construct "
                    "arbitrary JS types from the input.",
                    "Pass {schema: JSON_SCHEMA} (or the older yaml.safeLoad).",
                ))

            for pat in (_JS_FETCH_CALL, _JS_AXIOS_CALL, _JS_HTTP_GET_CALL):
                m3 = pat.search(line)
                if not m3:
                    continue
                arg = js_util.first_call_arg(line, m3.end() - 1)
                if arg and not js_util.is_const_arg(arg) and not has_allowlist:
                    out.append(self._f(
                        "ssrf",
                        "HTTP fetch of a caller-influenced URL with no host allowlist",
                        Severity.P2, Confidence.MEDIUM, f, i,
                        "A tool that fetches a caller-supplied URL can be pointed "
                        "at internal/metadata endpoints (SSRF).",
                        "Validate the URL against a host allowlist; reject "
                        "non-http(s) schemes and private/link-local IP ranges "
                        "before fetching.",
                    ))
                break

            mfs = _JS_FS_PATH_CALL.search(line)
            if mfs:
                arg = js_util.first_call_arg(line, mfs.end() - 1)
                if arg and not js_util.is_const_arg(arg) and not has_containment:
                    out.append(self._f(
                        "path-traversal",
                        "file op on a non-constant path without containment",
                        Severity.P2, Confidence.LOW, f, i,
                        "A tool that opens a caller-derived path with no "
                        "confinement (path.resolve + a containment check) may "
                        "allow ../ traversal outside its intended directory.",
                        "Resolve the path and assert it stays under an allowed "
                        "base directory before opening.",
                    ))
        return out

    @staticmethod
    def _js_is_real_exec_call(
        line: str,
        lineno: int,
        exec_aliases: set[str],
        bindings: list[tuple[str, str, int, int]],
    ) -> bool:
        """True when this line's exec(Sync)?( call is a real
        child_process invocation, not a RegExp.prototype.exec() match call
        wearing the same syntax. Receiver resolution, same-file-bounded
        AND scope-aware (round-2 N-vote P0-2 fix -- real-JS-shadowing-
        correct, see ``_resolve_receiver_kind``):

        - a captured receiver identifier (``NAME.exec(``): resolve
          ``NAME``'s kind at THIS line via ``_resolve_receiver_kind``.
          ``"regexp"`` -> demoted. ``"cp_module"`` or literally
          ``child_process`` -> real sink, flagged. Unresolved (no binding
          of this name visible at this line at all) -- stays flagged, the
          over-flag-safe direction;
        - no receiver at all but an inline regex literal immediately
          precedes ``.exec(``: demoted;
        - a genuinely bare call (``exec(cmd)``) or a destructured-alias
          call: real sink, flagged (unchanged from before this fix).
        """
        rec_m = _JS_EXEC_RECEIVER.search(line)
        if rec_m:
            receiver = rec_m.group(1)
            if receiver == "child_process":
                return True
            kind = _resolve_receiver_kind(bindings, receiver, lineno)
            return kind != "regexp"
        if _JS_REGEX_LITERAL_EXEC.search(line):
            return False
        if _JS_BARE_EXEC.search(line) or _js_alias_call(line, exec_aliases):
            return True
        return False

    def _check_call(
        self, node: ast.Call, f: SourceFile, has_containment: bool, has_allowlist: bool
    ) -> list[Finding]:
        out: list[Finding] = []
        name = _dotted(node.func)
        short = name.split(".")[-1]

        # --- shell=True -------------------------------------------------
        if "subprocess" in name or short in ("run", "call", "Popen", "check_output", "check_call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    out.append(self._f(
                        "shell-injection",
                        "subprocess called with shell=True",
                        Severity.P1, Confidence.HIGH, f, node.lineno,
                        "subprocess with shell=True runs its argument through /bin/sh; "
                        "any tool-controlled substring becomes shell metacharacters.",
                        "Use shell=False with a list argv. If a shell is unavoidable, "
                        "shlex.quote every interpolated value and reject metacharacters.",
                    ))

        # --- os.system / os.popen --------------------------------------
        if name in ("os.system", "os.popen"):
            const_arg = node.args and _is_constant_str(node.args[0])
            out.append(self._f(
                "shell-injection",
                f"{name} invocation",
                Severity.P1 if not const_arg else Severity.P3,
                Confidence.HIGH if not const_arg else Confidence.LOW,
                f, node.lineno,
                f"{name} runs a string through the shell.",
                "Replace with subprocess.run([...], shell=False).",
            ))

        # --- eval / exec ------------------------------------------------
        if short in ("eval", "exec") and name in ("eval", "exec"):
            if node.args and not _is_constant_str(node.args[0]):
                out.append(self._f(
                    "code-eval",
                    f"{short}() on a non-constant value",
                    Severity.P0, Confidence.HIGH, f, node.lineno,
                    f"{short}() executes arbitrary Python from its argument.",
                    f"Remove {short}(). Parse structured input explicitly "
                    "(ast.literal_eval for literals, a real parser otherwise).",
                ))

        # --- pickle -----------------------------------------------------
        if name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            out.append(self._f(
                "unsafe-deserialization",
                f"{name} deserializes untrusted data",
                Severity.P1, Confidence.MEDIUM, f, node.lineno,
                "pickle executes arbitrary code during deserialization.",
                "Never unpickle data crossing a trust boundary. Use json or a "
                "schema-validated format.",
            ))

        # --- yaml.load without SafeLoader ------------------------------
        if name in ("yaml.load", "yaml.load_all"):
            safe = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    ldr = _dotted(kw.value)
                    if "Safe" in ldr or "Base" in ldr:
                        safe = True
            if len(node.args) >= 2:  # positional Loader
                ldr = _dotted(node.args[1])
                if "Safe" in ldr or "Base" in ldr:
                    safe = True
            if not safe:
                out.append(self._f(
                    "unsafe-deserialization",
                    "yaml.load without SafeLoader",
                    Severity.P1, Confidence.MEDIUM, f, node.lineno,
                    "yaml.load with the default loader can construct arbitrary "
                    "Python objects.",
                    "Use yaml.safe_load() (or Loader=SafeLoader).",
                ))

        # --- HTTP fetch of a non-constant URL -> SSRF ------------------
        if name in (
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "requests.head", "requests.request", "httpx.get", "httpx.post",
            "urllib.request.urlopen", "urlopen",
        ):
            if node.args and not _is_constant_str(node.args[0]) and not has_allowlist:
                out.append(self._f(
                    "ssrf",
                    "HTTP fetch of a caller-influenced URL with no host allowlist",
                    Severity.P2, Confidence.MEDIUM, f, node.lineno,
                    "A tool that fetches a caller-supplied URL can be pointed at "
                    "internal/metadata endpoints or file:// (SSRF).",
                    "Validate the URL against a host allowlist; reject non-http(s) "
                    "schemes and private/link-local IP ranges before fetching.",
                ))

        # --- file op on a variable path, no containment ----------------
        if short == "open" and name in ("open", "io.open", "os.open", "pathlib.Path.open"):
            if node.args and not _is_constant_str(node.args[0]) and not has_containment:
                out.append(self._f(
                    "path-traversal",
                    "file opened on a non-constant path without containment",
                    Severity.P2, Confidence.LOW, f, node.lineno,
                    "A tool that opens a caller-derived path with no confinement "
                    "(realpath/commonpath check) may allow ../ traversal outside its "
                    "intended directory.",
                    "Resolve the path (realpath) and assert it stays under an allowed "
                    "base directory before opening.",
                ))

        return out

    def _f(self, vc, title, sev, conf, f: SourceFile, line, detail, remediation) -> Finding:
        return Finding(
            vuln_class=vc, title=title, severity=sev, confidence=conf,
            file=f.rel, line=line, detail=detail, remediation=remediation,
            snippet=f.line_at(line),
        )
