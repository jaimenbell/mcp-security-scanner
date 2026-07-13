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

from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

_CONTAINMENT_HINTS = (
    "realpath", "resolve", "commonpath", "commonprefix", "is_relative_to",
    "relative_to", "abspath", "safe_join", "secure_filename",
)
_ALLOWLIST_HINTS = (
    "allowlist", "allow_list", "whitelist", "ALLOWED", "allowed_hosts",
    "allowed_domains", "urlparse", "hostname", "netloc",
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
