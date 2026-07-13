"""Detector 1 — codegen / template injection.

The mcp-factory class: a tool that *generates source code* from untrusted
manifest fields, using a Jinja environment with autoescape OFF, and hand-rolled
string escaping (``replace('"','\\"')``) instead of a real serializer
(``repr`` / ``json.dumps``). Autoescape-off is *correct* for code templates, so
on its own it is only a surface; the danger is the combination with (a) template
files that interpolate free-text fields into code positions and (b) fragile
hand-escaping. We grade by how many of those signals co-occur.
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

# ``replace('"', '\\"')`` and friends — hand-rolled escaping of a quote/newline.
_HANDROLL_ESCAPE = re.compile(
    r"""replace\(\s*['"](?:\\+["'nrtu0]|["'])['"]"""
)
# A jinja expression ``{{ ... }}`` with no serializer filter (py_str/js_str/
# repr/tojson/json). Bare interpolation of a field into code text.
_JINJA_EXPR = re.compile(r"\{\{\s*(?P<inner>[^}]+?)\s*\}\}")
_SAFE_FILTERS = ("py_str", "js_str", "tojson", "json", "repr", "e", "forceescape")


def _autoescape_is_off(node: ast.Call) -> bool:
    """True if an Environment(...) call has autoescape disabled."""
    for kw in node.keywords:
        if kw.arg != "autoescape":
            continue
        val = kw.value
        # autoescape=False
        if isinstance(val, ast.Constant) and val.value is False:
            return True
        # autoescape=select_autoescape([])  -> escape nothing
        if isinstance(val, ast.Call):
            fn = val.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if fname == "select_autoescape":
                if not val.args or (
                    isinstance(val.args[0], (ast.List, ast.Tuple))
                    and len(val.args[0].elts) == 0
                ):
                    return True
        return False
    # autoescape omitted entirely -> Jinja default is False (off)
    return True


def _is_jinja_environment(node: ast.Call) -> bool:
    fn = node.func
    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
    return name == "Environment"


class CodegenInjectionDetector(Detector):
    name = "codegen-injection"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        py_files = [f for f in ctx.files if f.tree is not None]
        templates = [f for f in ctx.files if f.suffix in (".j2", ".jinja", ".jinja2")]

        has_codegen_templates = any(
            self._template_targets_code(t) for t in templates
        )

        for f in py_files:
            findings.extend(self._scan_python(f, has_codegen_templates))

        for t in templates:
            findings.extend(self._scan_template(t))

        return findings

    @staticmethod
    def _snap_line(f: SourceFile, guess: int, anchor: str) -> int:
        """Correct an AST lineno that a CPython f-string quirk shifted.

        If the guessed line does not contain the anchor token, search a window
        for the nearest line that does. Keeps report line:snippet honest.
        """
        if 1 <= guess <= len(f.lines) and anchor in f.lines[guess - 1]:
            return guess
        for radius in range(1, 12):
            for cand in (guess + radius, guess - radius):
                if 1 <= cand <= len(f.lines) and anchor in f.lines[cand - 1]:
                    return cand
        return guess

    # --- Python: Jinja Environment with autoescape off -------------------
    def _scan_python(self, f: SourceFile, has_codegen_templates: bool) -> list[Finding]:
        out: list[Finding] = []
        assert f.tree is not None
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Call) and _is_jinja_environment(node):
                if _autoescape_is_off(node):
                    lineno = self._snap_line(f, node.lineno, "Environment(")
                    # Severity depends on whether templates emit code from
                    # free-text fields. Autoescape-off feeding a code template
                    # is the real mcp-factory surface.
                    if has_codegen_templates:
                        sev, conf = Severity.P1, Confidence.MEDIUM
                        detail = (
                            "Jinja Environment has autoescape disabled and the repo "
                            "renders templates into source-code files. Untrusted "
                            "manifest/tool fields interpolated into generated code can "
                            "break out of string/comment/docstring context "
                            "(the mcp-factory codegen-injection class)."
                        )
                    else:
                        sev, conf = Severity.P2, Confidence.LOW
                        detail = (
                            "Jinja Environment has autoescape disabled. Safe for pure "
                            "code/text templates, but any HTML/untrusted output path "
                            "would be injectable."
                        )
                    out.append(
                        Finding(
                            vuln_class=self.name,
                            title="Jinja autoescape disabled in a code-generating tool",
                            severity=sev,
                            confidence=conf,
                            file=f.rel,
                            line=lineno,
                            detail=detail,
                            remediation=(
                                "Do not rely on autoescape for code templates. Render "
                                "every string/comment/docstring slot through a real "
                                "serializer (repr() for Python literals, json.dumps for "
                                "JS) and charset-validate identifier fields at parse "
                                "time. Never hand-roll quote escaping."
                            ),
                            snippet=f.line_at(lineno),
                        )
                    )
        return out

    # --- Templates: bare interpolation + hand-rolled escaping ------------
    def _scan_template(self, t: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        for i, line in enumerate(t.lines, start=1):
            if _HANDROLL_ESCAPE.search(line):
                out.append(
                    Finding(
                        vuln_class=self.name,
                        title="Hand-rolled string escaping in a code template",
                        severity=Severity.P1,
                        confidence=Confidence.MEDIUM,
                        file=t.rel,
                        line=i,
                        detail=(
                            "A template escapes untrusted text with replace(...) rather "
                            "than a serializer. Hand-rolled escaping is routinely "
                            "defeatable (a trailing backslash escapes the escape; "
                            "non-\\n line terminators \\r/U+2028/U+2029 survive)."
                        ),
                        remediation=(
                            "Replace hand-rolled escaping with a serializer filter: "
                            "repr()-backed for Python string literals, json.dumps for "
                            "JS string literals. For comment/docstring slots, strip the "
                            "full Unicode line-terminator class and the closing "
                            "delimiter, or move the value into a proper string literal."
                        ),
                        snippet=line.strip(),
                    )
                )
        return out

    @staticmethod
    def _template_targets_code(t: SourceFile) -> bool:
        """Heuristic: does this template emit Python/JS/TS source?"""
        name = t.path.name.lower()
        if any(x in name for x in (".py.", ".js.", ".ts.", "_server", "fastmcp")):
            return True
        # Content signal: python/JS keywords in the template body.
        body = t.text
        code_markers = ("import ", "def ", "async def", "require(", "const ", "class ")
        return sum(m in body for m in code_markers) >= 2

    @staticmethod
    def _expr_has_safe_filter(inner: str) -> bool:
        return any(f"| {flt}" in inner or f"|{flt}" in inner for flt in _SAFE_FILTERS)
