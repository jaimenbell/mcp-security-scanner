"""Detector 3 — auth / network posture.

* network bind on ``0.0.0.0`` (P2; escalates to P1 when paired with debug=True)
* ``debug=True`` on a web app / ``.run(...)`` (Werkzeug console == RCE)
* mutating HTTP routes (POST/PUT/DELETE/PATCH) with no auth dependency present
  in the file  -> unauthenticated mutation (P2, low/medium confidence)
* no rate limiter present in a networked server  -> hardening nit (P3)
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

_BIND_ALL = "0.0.0.0"
_AUTH_HINTS = (
    "Depends", "require_", "auth", "Security", "api_key", "token", "hmac",
    "compare_digest", "verify", "Authorization", "gated", "@gated_write",
)
_RATELIMIT_HINTS = ("ratelimit", "rate_limit", "limiter", "token_bucket", "slowapi", "throttle")
_MUTATING_DECOS = re.compile(r"\.(post|put|delete|patch)\b", re.IGNORECASE)


class AuthPostureDetector(Detector):
    name = "auth-posture"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        repo_binds_network = False

        for f in ctx.files:
            if f.tree is None:
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

        # no rate limiter in a networked server
        if repo_binds_network:
            has_rl = any(
                any(h in f.text.lower() for h in _RATELIMIT_HINTS)
                for f in ctx.files if f.tree is not None
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
