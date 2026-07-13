"""Detector 4 — secret handling.

* a tracked ``.env`` (or ``*.key`` / ``*.pem`` / keypair json) in git
* hardcoded secret literals in tracked source (API keys, private-key headers,
  ``SECRET_KEY = "literal"`` assignments to a real-looking value)
* secrets printed/logged (``print``/``log*`` of a token/secret/password var)

Whole-history git checks are intentionally out of scope for the static pass;
this operates on the tracked working tree and flags what a client can see today.
"""

from __future__ import annotations

import ast
import re

from ..models import Finding, Severity, Confidence
from .base import Detector, RepoContext, SourceFile

# High-signal secret material patterns (value shapes, not names).
_SECRET_VALUE_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI-style secret key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
]

_SECRET_NAME = re.compile(
    r"(secret|token|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
# Values that are obviously placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"^(|x+|your[_-]?|<.*>|\.\.\.|changeme|placeholder|example|dummy|test|none|null|"
    r"\$\{.*\}|env\[|os\.environ|getenv)",
    re.IGNORECASE,
)
_LOG_CALLS = ("print", "log.info", "log.debug", "log.warning", "log.error",
              "logger.info", "logger.debug", "logger.warning", "logger.error",
              "logging.info", "logging.debug", "logging.warning", "logging.error")

_TRACKED_SECRET_FILES = (
    re.compile(r"(^|/)\.env$"),
    re.compile(r"(^|/)\.env\.[A-Za-z0-9_]+$"),  # .env.local, .env.prod (not .env.example)
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"keypair.*\.json$"),
    re.compile(r"(^|/)id_rsa$"),
)
_EXAMPLE_ENV = re.compile(r"\.env\.(example|sample|template|dist)$")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


class SecretHandlingDetector(Detector):
    name = "secret-handling"

    def run(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1) tracked secret files
        for rel in sorted(ctx.tracked):
            if _EXAMPLE_ENV.search(rel):
                continue
            for pat in _TRACKED_SECRET_FILES:
                if pat.search(rel):
                    findings.append(Finding(
                        vuln_class="tracked-secret-file",
                        title=f"Secret-bearing file tracked in git: {rel}",
                        severity=Severity.P1, confidence=Confidence.HIGH,
                        file=rel, line=0,
                        detail="A file that conventionally holds live credentials is "
                               "committed to the repo; anyone with clone access reads it.",
                        remediation="Remove from tracking (git rm --cached), add to "
                                    ".gitignore, rotate the exposed credential, and "
                                    "scrub git history.",
                    ))
                    break

        # 2) source content
        for f in ctx.files:
            findings.extend(self._scan_literals(f))
            if f.tree is not None:
                findings.extend(self._scan_logging(f))

        return findings

    def _scan_literals(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        # value-shape matches on raw text (catches non-python too)
        for i, line in enumerate(f.lines, start=1):
            for pat, what in _SECRET_VALUE_PATTERNS:
                if pat.search(line):
                    out.append(Finding(
                        vuln_class="hardcoded-secret",
                        title=f"Hardcoded {what} in source",
                        severity=Severity.P1, confidence=Confidence.HIGH,
                        file=f.rel, line=i,
                        detail=f"A {what} appears as a literal in tracked source.",
                        remediation="Move to an environment variable / secret store, "
                                    "rotate the exposed value, and scrub history.",
                        snippet="<redacted secret line>",
                    ))
        # AST: NAME = "literal" where NAME looks secret and value looks real
        if f.tree is not None:
            for node in ast.walk(f.tree):
                if isinstance(node, ast.Assign):
                    val = node.value
                    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
                        continue
                    if _PLACEHOLDER.match(val.value.strip()) or len(val.value.strip()) < 8:
                        continue
                    for tgt in node.targets:
                        nm = _dotted(tgt)
                        if nm and _SECRET_NAME.search(nm):
                            out.append(Finding(
                                vuln_class="hardcoded-secret",
                                title=f"Hardcoded secret assigned to '{nm}'",
                                severity=Severity.P1, confidence=Confidence.MEDIUM,
                                file=f.rel, line=node.lineno,
                                detail=f"'{nm}' is assigned a non-placeholder string "
                                       "literal; likely a committed credential.",
                                remediation="Read from os.environ / a secret store; "
                                            "rotate and scrub if this was ever real.",
                                snippet="<redacted secret assignment>",
                            ))
        return out

    def _scan_logging(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        assert f.tree is not None
        for node in ast.walk(f.tree):
            if isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name in _LOG_CALLS or name.split(".")[-1] in ("print",):
                    if self._arg_mentions_secret(node):
                        out.append(Finding(
                            vuln_class="secret-in-log",
                            title="Secret-named value passed to a log/print call",
                            severity=Severity.P2, confidence=Confidence.LOW,
                            file=f.rel, line=node.lineno,
                            detail="A variable whose name suggests a credential is "
                                   "logged/printed; secrets can leak into log files or "
                                   "tool output.",
                            remediation="Never log credentials. Redact to a fixed mask "
                                        "or a boolean 'present/absent'.",
                            snippet=f.line_at(node.lineno),
                        ))
        return out

    def _arg_mentions_secret(self, call: ast.Call) -> bool:
        for a in list(call.args) + [kw.value for kw in call.keywords]:
            for sub in ast.walk(a):
                if isinstance(sub, ast.Name) and _SECRET_NAME.search(sub.id):
                    return True
                if isinstance(sub, ast.Attribute) and _SECRET_NAME.search(sub.attr):
                    return True
        return False
