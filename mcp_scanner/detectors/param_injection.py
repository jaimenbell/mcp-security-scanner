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
_JS_EXEC_CALL = re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\(")
_JS_SPAWN_EXECFILE_CALL = re.compile(r"\b(?:child_process\.)?(?:spawn|execFile)(?:Sync)?\s*\(")

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
        has_containment = any(h in text for h in _CONTAINMENT_HINTS)
        has_allowlist = any(h in text for h in _ALLOWLIST_HINTS)

        for i, raw_line in enumerate(f.lines, start=1):
            if js_util.is_comment_line(raw_line):
                continue
            line = js_util.code_part(raw_line)

            if has_child_process:
                if _JS_EXEC_CALL.search(line) or _js_alias_call(line, exec_aliases):
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
