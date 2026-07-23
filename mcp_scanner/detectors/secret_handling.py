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
from .. import js_util
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

# --- JS/TS parity: secret-named value passed to a log call -----------------
# No AST for JS/TS in this scanner. Line-based, and deliberately restricted
# to non-string-literal text on the call's argument side, mirroring the
# Python path's AST check (Name/Attribute *identifiers* only -- log MESSAGE
# prose that happens to mention "token" must never trigger this, only an
# actual secret-named variable/property passed as an argument).
_JS_LOG_CALL = re.compile(
    r"\b(?:console\.(?:log|error|warn|info|debug)|"
    r"logger\.(?:log|info|debug|warn|error)|"
    r"log\.(?:info|debug|warn|error))\s*\("
)
_JS_STRING_LITERAL = re.compile(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`""")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _js_template_interpolations(text: str) -> list[str]:
    """Raw expression text inside every ``${...}`` interpolation found
    within a backtick TEMPLATE literal in ``text``.

    Only backtick spans are inspected -- a '${' inside a plain '...'/"..."
    string is literal text in real JS (no interpolation there), so it is
    deliberately never treated as one; a fixture proves this stays quiet
    rather than false-positiving or crashing on it. Nested braces inside
    the interpolation (e.g. an object literal) are depth-tracked so the
    extraction doesn't cut short at the first inner '}'.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            quote = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "`":
            i += 1
            while i < n and text[i] != "`":
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    depth = 1
                    j = i + 2
                    start = j
                    while j < n and depth > 0:
                        if text[j] == "{":
                            depth += 1
                        elif text[j] == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    out.append(text[start:j])
                    i = j + 1
                    continue
                i += 1
            i += 1  # skip closing backtick (or run off the end -- best-effort)
            continue
        i += 1
    return out


# --- Wave-1 FP fix (a): pagination/continuation-cursor field names --------
# Evidence (staged/ecosystem-scan-2026-07-23): every non-test
# secret-leak-via-tool-response finding in the ecosystem scan was a
# `next_token`/`cursor`-style pagination field -- an opaque, server-issued
# continuation handle, not a credential (e.g. AWS's own
# `ListTranslationJobs` pagination token). Demotion requires BOTH the
# pagination word-shape (next/page/continuation combined with token/cursor,
# or a bare 'cursor') AND the absence of any stronger credential word in the
# same identifier -- ``access_token``/``refresh_token``/``client_secret``/
# ``page_token_secret`` never demote even though they also contain
# token/page/cursor substrings, because the credential word is still there.
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_PAGINATION_PREFIX_WORDS = {"next", "page", "continuation"}
_PAGINATION_CORE_WORDS = {"token", "cursor"}
_PAGINATION_EXCLUDE_WORDS = {
    "access", "refresh", "auth", "secret", "password", "passwd", "client",
    "bearer", "session", "private", "csrf", "id", "api", "key",
}


def _name_words(name: str) -> list[str]:
    """Split an identifier into lowercase words on underscores/hyphens and
    camelCase boundaries -- e.g. ``result_next_token`` or ``resultNextToken``
    both become ``["result", "next", "token"]``."""
    split = _CAMEL_BOUNDARY.sub("_", name)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", split) if w]


def _is_pagination_cursor_name(name: str) -> bool:
    words = set(_name_words(name))
    if not words:
        return False
    if words & _PAGINATION_EXCLUDE_WORDS:
        return False
    if "cursor" in words:
        return True
    if (words & _PAGINATION_PREFIX_WORDS) and (words & _PAGINATION_CORE_WORDS):
        return True
    return False


def _name_looks_secret(name: str) -> bool:
    """``_SECRET_NAME`` (reused as-is) with a word-boundary guard so a
    substring glued inside a longer, unrelated word doesn't count -- e.g.
    ``tokenizer_version``/``passwordless_mode`` (glued continuation letters)
    or ``apiKeyValidator``/``tokenizerConfig`` (glued compound-word letters,
    camelCase or not -- ANY letter immediately touching either side of the
    match with no separator means it isn't a standalone secret-name hit).
    A legitimate whole-word hit like ``SECRET_KEY`` or ``api_key`` (where
    what follows/precedes is a separator, or nothing) still fires. Shared by
    every detector that does secret-name matching on an identifier, so the
    rejection logic lives in one place, not one copy per call site."""
    if not name:
        return False
    m = _SECRET_NAME.search(name)
    if not m:
        return False
    start, end = m.span()
    before = name[start - 1] if start > 0 else ""
    after = name[end] if end < len(name) else ""
    if before.isalpha():
        return False
    if after.isalpha():
        return False
    if _is_pagination_cursor_name(name):
        return False
    return True


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
            elif f.suffix in js_util.JS_SUFFIXES:
                findings.extend(self._scan_js_logging(f))

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

    def _scan_js_logging(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        for i, raw_line in enumerate(f.lines, start=1):
            if js_util.is_comment_line(raw_line):
                continue
            line = js_util.code_part(raw_line)
            m = _JS_LOG_CALL.search(line)
            if not m:
                continue
            arg_text = line[m.end():]
            # Template-literal interpolations (P2 fix, 2026-07-22 verify
            # pass): `${apiKey}` is real code, not message prose, but the
            # blanket string-strip below treats the WHOLE backtick span as
            # one opaque literal and deletes it -- pull the ${...} contents
            # back out first so an interpolated secret identifier survives.
            interpolations = _js_template_interpolations(arg_text)
            # Strip string-literal contents so log MESSAGE prose (e.g.
            # "token required but not shown") never triggers this -- only an
            # actual identifier/property name matching the secret-name
            # heuristic does.
            code_only = _JS_STRING_LITERAL.sub("", arg_text)
            if interpolations:
                code_only = code_only + " " + " ".join(interpolations)
            # Word-boundary-aware (cheap-win fix, 2026-07-22): a bare
            # _SECRET_NAME.search would also fire on a name that merely
            # CONTAINS a secret-vocabulary substring glued inside a longer,
            # unrelated identifier (apiKeyValidator.isValid,
            # tokenizerConfig.version) -- check each identifier token
            # against the same word-boundary guard the sibling
            # secret-leak-via-tool-response detector already uses.
            if any(_name_looks_secret(tok) for tok in _IDENT.findall(code_only)):
                out.append(Finding(
                    vuln_class="secret-in-log",
                    title="Secret-named value passed to a log call",
                    severity=Severity.P2, confidence=Confidence.LOW,
                    file=f.rel, line=i,
                    detail="A variable whose name suggests a credential is "
                           "logged/printed; secrets can leak into log files or "
                           "tool output.",
                    remediation="Never log credentials. Redact to a fixed mask "
                                "or a boolean 'present/absent'.",
                    snippet=f.line_at(i),
                ))
        return out

    def _arg_mentions_secret(self, call: ast.Call) -> bool:
        # Wave-1 fix: route through the shared _name_looks_secret helper
        # (word-boundary + pagination-cursor guard) instead of a raw
        # _SECRET_NAME.search -- this call site was the one Python path that
        # still bypassed both guards, and is the exact site the ecosystem
        # scan's `logger.debug(f'Received next_token: ...')` FP came through.
        for a in list(call.args) + [kw.value for kw in call.keywords]:
            for sub in ast.walk(a):
                if isinstance(sub, ast.Name) and _name_looks_secret(sub.id):
                    return True
                if isinstance(sub, ast.Attribute) and _name_looks_secret(sub.attr):
                    return True
        return False
