"""Detector 3 — auth / network posture.

* network bind on ``0.0.0.0`` (P2; escalates to P1 when paired with debug=True)
* JS/TS network bind with no host argument -- ``app.listen(port)`` (P2;
  escalates to P1 when the same file serves a mutating HTTP route with no
  auth evidence in code)
* ``debug=True`` on a web app / ``.run(...)`` (Werkzeug console == RCE)
* mutating HTTP routes (POST/PUT/DELETE/PATCH) with no auth dependency present
  in the file  -> unauthenticated mutation (P2, low/medium confidence)
* no rate limiter present in a networked server  -> hardening nit (P3)

WHICH CHECKS RUN ON WHICH LANGUAGE, and why (2026-07-30 recall slice 2)
----------------------------------------------------------------------
``run`` used to open with ``if f.tree is None: continue``, so the whole
detector was switched off on every ``.ts``/``.js`` file -- a structural gate,
not an analytical one.  The 2026-07-30 five-target hand audit found what that
cost: ``airtable-mcp-server`` ``src/main.ts:35-57`` serves ``POST /mcp`` over
``app.listen(port, callback)`` with no auth, no Origin validation and no
DNS-rebinding protection, granting full read/write on the operator's Airtable
account through the server's own PAT.  The detector for that class existed and
never ran.  The bind check also keyed on the literal ``_BIND_ALL = "0.0.0.0"``,
which ``app.listen(port)`` binds without ever containing.

Un-gated (genuinely text-shaped, so the JS answer means the same thing as the
Python one):

  * the ``0.0.0.0`` literal
  * "does this repo bind a network interface at all", which feeds the
    repo-level rate-limiter check -- previously only a Python file could set it

Deliberately still Python-only, because these read Python AST semantics that
have no JS analogue.  Extrapolating them would put a false statement in a
report, which is worse than the gap:

  * ``debug=True``.  The P1 rationale is Werkzeug's interactive debugger
    ("an unhandled exception yields remote code execution").  A ``debug: true``
    property in a JS options object does not mean that.
  * the mutating-route walk.  It reads Python decorators and inspects the
    handler's SIGNATURE for ``Depends``/``Security`` -- a FastAPI/Flask
    dependency-injection concept.  JS auth is middleware, not a signature.

Every hint judgement on JS text runs on ``js_util.code_only`` (comments and
string CONTENTS removed).  Matching raw text would have silenced the airtable
finding outright: the only occurrence of the word ``auth`` in that file is the
console warning *"HTTP transport has no authentication"*, so a file-wide
substring test would have accepted a warning ABOUT missing auth as proof that
auth exists.
"""

from __future__ import annotations

import ast
import re

from .. import js_util
from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

_BIND_ALL = "0.0.0.0"
_AUTH_HINTS = (
    "Depends", "require_", "auth", "Security", "api_key", "token", "hmac",
    "compare_digest", "verify", "Authorization", "gated", "@gated_write",
)
_RATELIMIT_HINTS = ("ratelimit", "rate_limit", "limiter", "token_bucket", "slowapi", "throttle")
_MUTATING_DECOS = re.compile(r"\.(post|put|delete|patch)\b", re.IGNORECASE)

# --- JS/TS network-bind detection (2026-07-30 recall slice 2) ------------
# `app.listen(...)` / `httpServer.listen(...)`. The `(` must follow `listen`
# immediately-modulo-whitespace, so `emitter.listeners(...)` and
# `el.addEventListener(...)` cannot match.
_JS_LISTEN_RE = re.compile(r"\b[\w$]+\.listen\s*\(")
# A second argument that is a FUNCTION rather than a host -- Node's
# `listen(port, callback)` overload. This is airtable's exact shape and the
# reason a "does it pass a host?" check has to look at the argument's SHAPE,
# not merely its presence.
_JS_FUNCTION_ARG_RE = re.compile(r"^\s*(?:async\s+)?(?:function\b|\(|[\w$]+\s*=>)")
# Host values that mean "every interface" when passed explicitly.
_JS_BIND_ALL_HOSTS = frozenset({"0.0.0.0", "::", ""})
# MCP HTTP-transport hardening controls. Their ABSENCE is reported as context
# on a bind finding, never as a finding of its own.
_JS_REBIND_GUARDS = ("enableDnsRebindingProtection", "allowedOrigins", "allowedHosts")
# SCOPE of the JS ``0.0.0.0`` literal check, stated with the pattern.  A bare
# substring test over JS text matches prose: in notion-mcp-server it hit four
# lines of a *warning message* that says the string ("WARNING: unauthenticated
# HTTP is bound to 0.0.0.0...") and a display helper that COMPARES against it
# to rewrite it to loopback.  Neither binds anything.  So the literal counts
# only when (a) it is the ENTIRE string value, not a word inside a sentence,
# and (b) it is not the right-hand side of an equality test or a `case` label
# -- checking for a value is the opposite of setting it.
_JS_HOST_COMPARISON = re.compile(r"(?:[=!]==?|\bcase)\s*$")


class AuthPostureDetector(Detector):
    name = "auth-posture"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        repo_binds_network = False

        for f in ctx.files:
            if f.tree is None:
                if f.suffix in js_util.JS_SUFFIXES:
                    js_findings, js_binds = self._scan_js(f)
                    findings.extend(js_findings)
                    repo_binds_network = repo_binds_network or js_binds
                continue
            text = f.text
            debug_true = self._has_debug_true(f)
            binds_all = _BIND_ALL in text
            if binds_all:
                repo_binds_network = True

            # 0.0.0.0 bind
            for lineno in self._string_literal_lines(f, _BIND_ALL):
                if debug_true:
                    findings.append(self._f(
                        "network-exposure",
                        "Binds 0.0.0.0 with debug enabled",
                        Severity.P1, Confidence.HIGH, f, lineno,
                        "Binding all interfaces (0.0.0.0) with debug=True exposes an "
                        "interactive debugger (RCE via PIN) to the whole LAN/tailnet.",
                        "Bind 127.0.0.1 by default; require explicit env opt-in for "
                        "0.0.0.0. Force debug=False in anything network-reachable.",
                    ))
                else:
                    findings.append(self._f(
                        "network-exposure",
                        "Binds all interfaces (0.0.0.0)",
                        Severity.P2, Confidence.MEDIUM, f, lineno,
                        "Binding 0.0.0.0 makes the server reachable from every LAN/"
                        "tailnet host, not just loopback.",
                        "Default-bind 127.0.0.1; gate 0.0.0.0 behind an explicit env "
                        "opt-in.",
                    ))

            # debug=True (independent of bind, still risky)
            for lineno in self._debug_true_lines(f):
                findings.append(self._f(
                    "debug-console",
                    "Web app run with debug=True",
                    Severity.P1 if binds_all else Severity.P2,
                    Confidence.MEDIUM, f, lineno,
                    "debug=True enables the Werkzeug interactive debugger; an "
                    "unhandled exception yields remote code execution.",
                    "Force debug=False in production; gate any dev console behind a "
                    "separate, loopback-only flag.",
                ))

            # unauthenticated mutating routes
            findings.extend(self._mutating_routes(f))

        # no rate limiter in a networked server.  JS/TS files are consulted
        # here too now (previously only ``f.tree is not None`` files were, so a
        # JS-only server could neither set ``repo_binds_network`` nor be
        # credited for having a limiter).  JS text is comment/string-stripped
        # first: a `// TODO: add a rate_limit` is not a rate limiter.
        if repo_binds_network:
            has_rl = any(
                any(h in self._hint_text(f).lower() for h in _RATELIMIT_HINTS)
                for f in ctx.files
                if f.tree is not None or f.suffix in js_util.JS_SUFFIXES
            )
            if not has_rl:
                findings.append(Finding(
                    vuln_class="no-rate-limit",
                    title="Network server with no rate limiter",
                    severity=Severity.P3, confidence=Confidence.LOW,
                    file=".", line=0,
                    detail="No rate-limiting primitive was found in a server that binds "
                           "a network interface; mutating tools can be hammered.",
                    remediation="Add a token-bucket / per-client rate limit on mutating "
                                "tools and auth attempts.",
                ))
        return findings

    # --- JS/TS -----------------------------------------------------------
    @staticmethod
    def _hint_text(f: SourceFile) -> str:
        """The text a "is there evidence of X in this file" test may read.

        Python: the file as-is (its checks are AST-backed elsewhere and this
        preserves existing behaviour exactly). JS/TS: comments and string
        CONTENTS removed -- see the module docstring for why a raw-text
        substring test is not admissible evidence on this surface.
        """
        if f.tree is not None:
            return f.text
        return "\n".join(js_util.code_only(line) for line in f.lines)

    def _scan_js(self, f: SourceFile) -> tuple[list[Finding], bool]:
        """Network-bind posture for one JS/TS file.

        Returns ``(findings, binds_network)``. Two bind shapes, and one
        finding per bind SITE -- an explicit ``'0.0.0.0'`` on a listen line is
        reported once by the literal path, never again by the host-shape path.
        """
        out: list[Finding] = []
        code = self._hint_text(f)
        file_has_auth = any(h in code for h in _AUTH_HINTS)
        file_has_mutating_route = bool(_MUTATING_DECOS.search(code))
        rebind_guarded = any(g in code for g in _JS_REBIND_GUARDS)

        # 1. An explicit all-interfaces host literal, anywhere in the file.
        #    Mirrors the Python ``_string_literal_lines`` check.
        bind_all_lines: set[int] = set()
        for i, raw in enumerate(f.lines, start=1):
            if js_util.is_comment_line(raw):
                continue
            line = js_util.code_part(raw)
            if _BIND_ALL in line and any(
                m.group(0)[1:-1] == _BIND_ALL
                and not _JS_HOST_COMPARISON.search(line[:m.start()])
                for m in js_util._STR_LITERAL.finditer(line)
            ):
                bind_all_lines.add(i)
                out.append(self._f(
                    "network-exposure",
                    "Binds all interfaces (0.0.0.0)",
                    Severity.P2, Confidence.MEDIUM, f, i,
                    "Binding 0.0.0.0 makes the server reachable from every LAN/"
                    "tailnet host, not just loopback.",
                    "Default-bind 127.0.0.1; gate 0.0.0.0 behind an explicit env "
                    "opt-in.",
                ))

        # 2. A `.listen(...)` whose host argument is absent or is a callback.
        #    Node binds every interface in both cases, with no `0.0.0.0`
        #    string anywhere -- the gap the literal check above cannot see.
        binds = bool(bind_all_lines)
        for i, raw in enumerate(f.lines, start=1):
            if js_util.is_comment_line(raw):
                continue
            line = js_util.code_part(raw)
            m = _JS_LISTEN_RE.search(line)
            if not m:
                continue
            binds = True
            if i in bind_all_lines:
                continue  # already reported by the literal path
            args = js_util.call_args(line, m.end() - 1)
            first = args[0].strip() if args else ""
            if first.startswith("{"):
                # `listen({ port, host })` -- the options-object overload.
                # Reading a host out of it needs a parser this scanner does
                # not have, so it is UNKNOWN, never assumed all-interfaces.
                continue
            host = args[1].strip() if len(args) > 1 else ""
            if host and not _JS_FUNCTION_ARG_RE.match(host):
                if not js_util.is_const_arg(host):
                    # A variable/expression host: unknown, not all-interfaces.
                    continue
                if host[1:-1] not in _JS_BIND_ALL_HOSTS:
                    continue  # a specific host was requested

            unauth_mutation = file_has_mutating_route and not file_has_auth
            detail = (
                "This listener passes no host argument (the second argument is "
                "a callback, not a host), so Node binds EVERY interface -- the "
                "server is reachable from the whole LAN/tailnet, not just "
                "loopback. No `0.0.0.0` literal appears in the file, which is "
                "why a literal-keyed bind check does not see this."
            )
            if unauth_mutation:
                detail += (
                    " The same file also registers a mutating HTTP route "
                    "(POST/PUT/DELETE/PATCH) and contains no authentication "
                    "primitive in code (string literals and comments were "
                    "stripped before this judgement), so the route appears to "
                    "be an unauthenticated, LAN-reachable mutation path."
                )
            if not rebind_guarded:
                detail += (
                    " No DNS-rebinding/Origin control "
                    "(enableDnsRebindingProtection / allowedOrigins / "
                    "allowedHosts) is configured in this file either, so a "
                    "malicious web page can reach the listener through the "
                    "victim's browser."
                )
            out.append(self._f(
                "network-exposure",
                "Binds all interfaces (no host argument)",
                Severity.P1 if unauth_mutation else Severity.P2,
                Confidence.MEDIUM, f, i,
                detail,
                "Pass an explicit host: `listen(port, '127.0.0.1')`, and gate "
                "any all-interfaces bind behind an explicit env opt-in. If the "
                "listener must be network-reachable, require authentication on "
                "every route and enable the transport's DNS-rebinding/Origin "
                "protection.",
            ))
        return out, binds

    # --- helpers ----------------------------------------------------------
    def _mutating_routes(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        assert f.tree is not None
        file_has_auth = any(h in f.text for h in _AUTH_HINTS)
        for node in ast.walk(f.tree):
            if not isinstance(node, ast.FunctionDef) and not isinstance(node, ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                src = ast.unparse(deco) if hasattr(ast, "unparse") else ""
                if _MUTATING_DECOS.search(src):
                    # Does this route declare an auth dependency in its signature?
                    sig = ast.unparse(node.args) if hasattr(ast, "unparse") else ""
                    route_has_auth = any(h in sig for h in ("Depends", "Security", "auth", "token"))
                    if not route_has_auth and not file_has_auth:
                        out.append(self._f(
                            "missing-auth",
                            f"Mutating route '{node.name}' has no auth dependency",
                            Severity.P2, Confidence.LOW, f, node.lineno,
                            "A state-changing route (POST/PUT/DELETE/PATCH) has no "
                            "auth dependency and the module has no auth primitive; "
                            "it may be callable with zero credentials.",
                            "Add a default-deny auth dependency (Depends/Security) to "
                            "every mutating route, or a global auth middleware.",
                        ))
        return out

    def _has_debug_true(self, f: SourceFile) -> bool:
        return bool(self._debug_true_lines(f))

    def _debug_true_lines(self, f: SourceFile) -> list[int]:
        lines: list[int] = []
        assert f.tree is not None
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        lines.append(node.lineno)
            # FLASK_DEBUG default 'True' style string constants
            if isinstance(node, ast.Constant) and node.value in ("True", "true"):
                pass
        return lines

    def _string_literal_lines(self, f: SourceFile, needle: str) -> list[int]:
        lines: list[int] = []
        assert f.tree is not None
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and needle in node.value:
                lines.append(node.lineno)
        return lines

    def _f(self, vc, title, sev, conf, f: SourceFile, line, detail, remediation) -> Finding:
        return Finding(
            vuln_class=vc, title=title, severity=sev, confidence=conf,
            file=f.rel, line=line, detail=detail, remediation=remediation,
            snippet=f.line_at(line),
        )
