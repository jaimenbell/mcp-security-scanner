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
import functools
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
    # Round-2 N-vote P1-5 fix: value-shape backstop for name-based
    # demotions (pagination-cursor-name, etc.) -- a real bearer/JWT-shaped
    # secret assigned to a demoted name (e.g. `next_token = "eyJ..."`) had
    # NO other signal to catch it once the name-based check was
    # correctly suppressed. JWT: three base64url segments; the header
    # segment realistically starts `eyJ` (base64 of `{"`).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT-shaped token"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b"), "Bearer-prefixed token"),
]

# --- Round-3 N-vote P0-A fix: fake-marker DEMOTES, never suppresses ------
# Round-2's version of this guard (`_is_real_secret_value_match`) was an
# unanchored substring FULL-SUPPRESS (`continue`, no trace) -- exactly the
# "special-case exception to the one law" both refuters killed live:
# `PROD_API_KEY = "sample-tier-<68 real hex chars>"` (a genuine secret
# whose value merely CONTAINS "sample" as an unrelated tenant/tier
# component) vanished to zero findings. There is now exactly ONE rule in
# this whole module: full suppression is reserved for OUR OWN curated
# exact-match judgment (`_is_known_placeholder_secret`); every other
# signal -- pragma comments, fake-looking markers -- may only demote
# confidence to LOW and tag the finding, never drop it. Markers are
# word-boundary matched (bare substring matching was itself part of the
# round-2 failure) and applied uniformly to every `_SECRET_VALUE_PATTERNS`
# match, not gated to a special-cased subset of labels.
_FAKE_MARKER_WORDS = {"fake", "dummy", "placeholder", "sample", "demo", "test"}
_XXXX_MARKER = re.compile(r"x{4,}", re.IGNORECASE)


def _has_fake_marker(value: str) -> bool:
    """True when ``value`` contains an explicit fake/dummy/placeholder/
    sample/demo/test marker as a genuine WHOLE WORD, tokenized the same
    way ``_name_words`` tokenizes identifiers (splits on non-alphanumeric
    AND camelCase boundaries) -- NOT a naive regex ``\\b``, which treats
    underscore as a word character and so finds no boundary at all inside
    a snake_case identifier like ``github_pat_fake_test_token`` (the
    round-2 regression this replaces: the naive ``\\bfake\\b`` never
    matched real fixture values because they're underscore-joined).
    Separately checks for a run of 4+ ``x`` characters (a common
    "xxxxxxxx" placeholder shape that isn't a dictionary word). NEVER
    used to suppress -- see the module note above. A real secret
    occasionally DOES contain one of these words as an unrelated
    component (a tenant/tier name, a "test" environment label on a real
    credential) -- demotion, not suppression, is what keeps that case
    visible."""
    words = set(_name_words(value))
    if words & _FAKE_MARKER_WORDS:
        return True
    return bool(_XXXX_MARKER.search(value))


def _compose_demotion(conditions: list[tuple[bool, str]]) -> tuple["Confidence", str]:
    """``conditions``: [(is_true, tag_name), ...]. If ANY condition is
    True, confidence demotes to LOW and every true tag is joined into a
    single parenthesized title suffix (e.g. ``" (author-suppressed,
    fake-marker)"``); multiple independent demotion signals compose,
    they don't each get their own separate finding. Returns
    (Confidence.HIGH, "") when nothing demotes."""
    active = [tag for cond, tag in conditions if cond]
    if not active:
        return Confidence.HIGH, ""
    return Confidence.LOW, f" ({', '.join(active)})"

_SECRET_NAME = re.compile(
    r"(secret|token|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
# Values that are obviously placeholders, not real secrets.
#
# Round-2 N-vote P2-6 fix: the top-level alternation group used to open
# with an EMPTY alternative (``^(|x+|your...``) -- an empty string always
# satisfies a regex at position 0, so ``.match()`` was unconditionally
# truthy for ANY input. This silently blinded the entire AST
# ``NAME = "literal"`` hardcoded-secret-assignment branch below since
# 2026-07-13 (it never fired, for anything, ever) -- and meant wave-1's
# own "the placeholder demotion cannot mask a real secret" claim was
# resting on a branch that was never exercised. Fixed: the empty
# alternative is removed, and the pattern is applied via ``.fullmatch()``
# (not ``.match()``) at the call site so a value merely STARTING with a
# placeholder word (``"testing_a_real_leaked_credential"``) is no longer
# wrongly treated as a placeholder -- only a value that IS (in full) one
# of these placeholder shapes is excluded.
_PLACEHOLDER = re.compile(
    r"(x+|your[_-]?\w*|<.*>|\.\.\.+|changeme|placeholder|example|dummy|test|none|null|"
    r"\$\{.*\}|env\[.*\]|os\.environ.*|getenv\(.*\))",
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

# --- Wave-1 FP fix (b): self-signed TEST certificates ----------------------
# Evidence (staged/ecosystem-scan-2026-07-23): microsoft/playwright-mcp's
# tests/testserver/cert.pem + key.pem, a self-signed (issuer == subject)
# throwaway keypair committed purely to stand up a local HTTPS test server
# -- the common CI pattern, not a real secret leak. Demotion requires BOTH a
# test-fixture path AND a provable self-signed marker; a cert whose issuer
# != subject, or any cert outside a test-fixture path, is never demoted on
# "looks like a cert" alone.
_TEST_PATH_MARKER = re.compile(
    r"(^|/)(tests?|__tests__|testdata|test-data|testserver|fixtures?|spec|mocks?)(/|$)",
    re.IGNORECASE,
)
_CERT_SUFFIXES = (".pem", ".crt", ".cer")


def _is_test_fixture_path(rel: str) -> bool:
    return bool(_TEST_PATH_MARKER.search(rel))


def _try_import_cryptography():
    """Re-attempted on every call (cheap) -- deliberately NOT itself
    memoized, so a test that simulates ``cryptography`` being unavailable
    (monkeypatching ``__import__``) always genuinely re-checks rather than
    ever reusing a stale cached-available result from an earlier test in
    the same process. Returns the ``cryptography.x509`` module, or
    ``None``."""
    try:
        from cryptography import x509
        return x509
    except ImportError:
        return None


@functools.lru_cache(maxsize=None)
def _parse_x509_cert_bytes_cached(x509_mod, data: bytes):
    """The actual (expensive) parse, memoized on the exact bytes -- P3
    perf fix: re-parsing the same cert file repeatedly measured 4.65s on a
    200-cert-pair directory. Only ever called when ``x509_mod`` is already
    known non-None (see ``_parse_x509_cert``), so this cache can never
    mask a genuinely-unavailable-cryptography check."""
    try:
        return x509_mod.load_pem_x509_certificate(data)
    except Exception:
        return None


def _parse_x509_cert(path):
    """Parsed X.509 certificate for ``path``, or ``None`` on ImportError,
    a missing/unreadable file, or any parse error. The ``cryptography``
    availability check happens OUTSIDE the memoized parse step on every
    call -- see ``_try_import_cryptography`` -- so caching a successful
    parse from one test can never leak into a different test that's
    deliberately simulating the package's absence."""
    x509_mod = _try_import_cryptography()
    if x509_mod is None:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return _parse_x509_cert_bytes_cached(x509_mod, data)


def _is_self_signed_test_cert(path) -> bool:
    """True only when ``path`` parses as an X.509 certificate whose issuer
    equals its subject (the definition of self-signed). Requires the
    optional ``cryptography`` package; on ImportError, a missing/unreadable
    file, or any parse error, this returns False -- unknown always stays on
    the flagged side (over-flag-safe), never demoted on a guess."""
    cert = _parse_x509_cert(path)
    if cert is None:
        return False
    return cert.issuer == cert.subject


# --- Round-2 N-vote P0-4 fix, tightened round-3 (P0-B) --------------------
# issuer==subject alone is just "self-signed" -- true of a real internal-CA
# PRODUCTION root too -- and a test-fixture PATH is trivially true for an
# integration suite that embeds real staging/prod TLS material under
# tests/. Round-2's fix added a THIRD check but wired it as an OR-gate
# (marker OR short-validity OR weak-key): A2 reproduced the P0-4 scenario
# again verbatim at exactly the 90-day validity boundary (prod CN, normal
# 2048-bit key) -- validity alone satisfied the OR-gate and demoted it to
# total invisibility. Round-3 fix: the CN/SAN test-identity marker is now
# REQUIRED (no OR-gate); validity and key-size are not independently
# sufficient. A marker match is a real, checkable fact about the cert's
# own declared identity; a short validity window or a smaller key are
# common in PLENTY of legitimately-short-lived real internal certs too,
# so they were never strong enough to justify demoting alone.
_TEST_IDENTITY_MARKERS = re.compile(
    r"localhost|127\.0\.0\.1|::1|\.local$|\.test$|\.example$|\.invalid$|"
    r"\btest\b|\bdemo\b|\bexample\b|\bdummy\b|\bfixture\b|\bmock\b",
    re.IGNORECASE,
)


def _cert_identity_names(cert) -> list[str]:
    names: list[str] = []
    try:
        from cryptography.x509.oid import NameOID
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            names.append(str(cn_attrs[0].value))
    except Exception:
        pass
    try:
        from cryptography import x509 as x509_mod
        san_ext = cert.extensions.get_extension_for_class(x509_mod.SubjectAlternativeName)
        names.extend(str(n) for n in san_ext.value.get_values_for_type(x509_mod.DNSName))
    except Exception:
        pass
    return names


def _cert_has_test_shaped_identity(path) -> bool:
    """True when a self-signed cert at ``path`` ALSO looks test-shaped by
    content: its CN/SAN matches a localhost/test/example/demo/dummy/mock/
    fixture pattern. Round-3 N-vote P0-B fix: this marker is now REQUIRED
    -- round-2's version OR'd in a short (<= 90 day) validity window or a
    sub-2048-bit RSA key as INDEPENDENTLY sufficient, and A2 reproduced
    the original P0-4 scenario again verbatim right at the 90-day
    boundary (a prod-shaped CN, no marker, normal key size) -- validity
    alone satisfied the OR-gate and demoted a real-looking cert to total
    invisibility. Neither validity nor key size is a reliable enough
    signal to demote on its own (plenty of real, legitimately-short-lived
    certs exist); only the checkable, explicit CN/SAN marker is. Combined
    with the caller's separate issuer==subject + test-fixture-path
    checks, this is what stops a self-signed, prod-FQDN-shaped internal-CA
    root from demoting purely for living under a tests/ directory --
    while no longer letting validity/key-size alone stand in for that.
    Fails closed (False) on ImportError/parse error, same convention as
    every other cert check in this module."""
    cert = _parse_x509_cert(path)
    if cert is None:
        return False
    return any(_TEST_IDENTITY_MARKERS.search(n) for n in _cert_identity_names(cert))


def _looks_like_private_key_pem(path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "PRIVATE KEY-----" in text


# --- Wave-1 FP fix (c): known-placeholder credentials + suppress comments -
# Evidence (staged/ecosystem-scan-2026-07-23): awslabs/mcp's dynamodb-mcp-
# server hardcodes AWS's own canonical example access-key/secret-key pair
# (used throughout AWS's public docs to mean "put your real key here"),
# already marked by the maintainer with the detect-secrets `# pragma:
# allowlist secret` convention. Both mechanisms are curated/exact-match
# only -- never fuzzy/substring -- so a real secret that merely resembles a
# placeholder, or sits near an unrelated comment, still flags.
_KNOWN_PLACEHOLDER_SECRETS = frozenset({
    "AKIAIOSFODNN7EXAMPLE",                        # AWS docs' canonical example access-key id
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",     # AWS docs' canonical example secret-access-key
})
_SUPPRESS_COMMENT = re.compile(
    r"#\s*pragma:\s*allowlist secret|//\s*pragma:\s*allowlist secret",
    re.IGNORECASE,
)


def _is_known_placeholder_secret(value: str) -> bool:
    return value in _KNOWN_PLACEHOLDER_SECRETS


@functools.lru_cache(maxsize=None)
def _parse_private_key_bytes_cached(serialization_mod, data: bytes):
    """Memoized private-key parse, same convention as
    ``_parse_x509_cert_bytes_cached`` -- see that function's docstring for
    why the availability check stays outside the cache."""
    try:
        return serialization_mod.load_pem_private_key(data, password=None)
    except Exception:
        return None


def _parse_private_key(path):
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return _parse_private_key_bytes_cached(serialization, data)


def _private_key_matches_cert(key_path, cert_path) -> bool:
    """True only when the PEM private key at ``key_path`` cryptographically
    matches the public key embedded in the cert at ``cert_path`` (their
    SubjectPublicKeyInfo DER encodings are byte-identical). Directory
    co-location alone (same folder, both named cert.pem/key.pem by
    convention) is NOT proof they're a real pair -- an unrelated real
    production key could coincidentally sit beside an unrelated self-signed
    test cert. Requires the optional `cryptography` package; any
    ImportError, parse failure, or mismatch returns False (fails closed).

    P3 perf fix: routes through the SAME memoized parse helpers
    (``_parse_private_key`` / ``_parse_x509_cert``) the self-signed and
    test-shaped-identity checks already use, instead of re-parsing the
    cert from scratch a third time -- measured 4.65s on a 200-cert-pair
    directory before this fix."""
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return False
    private_key = _parse_private_key(key_path)
    cert = _parse_x509_cert(cert_path)
    if private_key is None or cert is None:
        return False
    try:
        priv_pub = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv_pub == cert_pub
    except Exception:
        return False


def _sibling_self_signed_cert(rel: str, root) -> bool:
    """Does the same directory as ``rel`` contain a sibling .pem/.crt/.cer
    file that is itself a provable self-signed cert AND test-shaped by
    content (round-2 N-vote P0-4, same requirement as the direct cert
    path), AND does the key at ``rel`` cryptographically match that cert's
    public key? Used to extend demotion to a cert's paired PRIVATE KEY file
    (key.pem next to cert.pem) -- the key itself carries no issuer/subject
    to check, but a throwaway keypair generated solely for a self-signed
    local test cert is the same low-risk shape as the cert it belongs to.
    Directory co-location alone is deliberately NOT sufficient -- see
    ``_private_key_matches_cert``."""
    try:
        key_path = root / rel
        d = key_path.parent
        if not d.is_dir():
            return False
        for sib in d.iterdir():
            if (
                sib.suffix.lower() in _CERT_SUFFIXES
                and _is_self_signed_test_cert(sib)
                and _cert_has_test_shaped_identity(sib)
            ):
                if _private_key_matches_cert(key_path, sib):
                    return True
    except OSError:
        return False
    return False

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
        #
        # Round-3 N-vote P0-B fix: cert demotion used to be a SILENT
        # BREAK (`break` -- skip the whole file, zero-trace) -- the exact
        # class of exception the "one law" rules out. Brought under it:
        # a demoted test cert still emits a finding, just LOW confidence
        # and tagged "(test-cert)", never zero-trace.
        for rel in sorted(ctx.tracked):
            if _EXAMPLE_ENV.search(rel):
                continue
            for pat in _TRACKED_SECRET_FILES:
                if pat.search(rel):
                    is_demoted = (
                        _is_test_fixture_path(rel)
                        and self._is_demoted_test_cert(rel, ctx.root)
                    )
                    confidence, tag_suffix = _compose_demotion([
                        (is_demoted, "test-cert"),
                    ])
                    detail = (
                        "A file that conventionally holds live credentials is "
                        "committed to the repo; anyone with clone access reads it."
                    )
                    if is_demoted:
                        detail += (
                            " It is self-signed, at a test-fixture path, and its own "
                            "content (CN/SAN) looks test-shaped -- likely, but not "
                            "provably, a throwaway keypair; confidence demoted rather "
                            "than the finding dropped."
                        )
                    findings.append(Finding(
                        vuln_class="tracked-secret-file",
                        title=f"Secret-bearing file tracked in git: {rel}{tag_suffix}",
                        severity=Severity.P1, confidence=confidence,
                        file=rel, line=0,
                        detail=detail,
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

    @staticmethod
    def _is_demoted_test_cert(rel: str, root) -> bool:
        """Called only after a tracked-secret-file pattern already matched
        AND the path is a test-fixture path. Returns True when the file is
        provably a self-signed cert that ALSO looks test-shaped by content
        (round-2 N-vote P0-4: self-signed + test-path alone discriminates
        nothing real -- see ``_cert_has_test_shaped_identity``), or a
        private key paired with one in the same directory -- never on
        extension/path alone."""
        low = rel.lower()
        if low.endswith((".pem", ".crt", ".cer")):
            abs_path = root / rel
            if _is_self_signed_test_cert(abs_path) and _cert_has_test_shaped_identity(abs_path):
                return True
            # Same extension, but not parseable as a cert -- may be the
            # paired PRIVATE KEY file (real-world convention: both cert and
            # key committed as "cert.pem"/"key.pem"). Check for a sibling
            # self-signed cert instead of trusting the extension alone.
            if _looks_like_private_key_pem(abs_path):
                return _sibling_self_signed_cert(rel, root)
            return False
        if low.endswith(".key") or rel.endswith("id_rsa"):
            return _sibling_self_signed_cert(rel, root)
        return False

    def _scan_literals(self, f: SourceFile) -> list[Finding]:
        out: list[Finding] = []
        # --- Wave-4 FP fix: test-path confidence demotion -------------------
        # Reviving the AST-assignment branch (round-2 P2-6) surfaced a large
        # new noise class on test-heavy repos: mostly mock/test credential
        # assignments in test files (`mock_credentials.token = "..."`). This
        # is one MORE demotion signal, composed via `_compose_demotion` --
        # NOT a special-case early return / suppression. A hardcoded-secret
        # finding whose file is a test-fixture path demotes to LOW + a
        # "(test-path)" tag; it is NEVER dropped. Critically, this demotes the
        # CONFIDENCE only: the value-shape backstop (AKIA.../ghp_.../-----BEGIN
        # PRIVATE KEY-----) below still FLAGS a real secret on a test path (LOW
        # at worst) -- a genuine leaked credential does not vanish just because
        # it lives under tests/. Same `_is_test_fixture_path` helper the cert
        # path already uses; computed once per file.
        is_test_path = _is_test_fixture_path(f.rel)
        # value-shape matches on raw text (catches non-python too).
        #
        # Round-2 N-vote P0-3 fix: this scanner's stated use case is
        # ADVERSARIAL/third-party scanning, not a cooperative repo owner --
        # `# pragma: allowlist secret` is a TARGET-authored, attacker-
        # controllable signal (a malicious external repo could otherwise
        # suppress its entire secret class with one comment per line) and
        # must NEVER fully suppress a finding on its own; it may only
        # demote confidence and tag the finding as author-suppressed so a
        # report still surfaces it. The CURATED placeholder list is OUR
        # OWN judgment (a short, reviewed, exact-match set of famous public
        # SDK-doc placeholders) and may still fully suppress.
        #
        # Also match-scoped, not line-scoped: `.finditer()` (not
        # `.search()`) so two DIFFERENT secret-shaped values on the same
        # line are each judged independently -- a real secret co-located
        # with a placeholder, or on a pragma-commented line, must not be
        # masked by the OTHER value's demotion.
        for i, line in enumerate(f.lines, start=1):
            has_suppress_comment = bool(_SUPPRESS_COMMENT.search(line))
            for pat, what in _SECRET_VALUE_PATTERNS:
                for m in pat.finditer(line):
                    value = m.group(0)
                    if _is_known_placeholder_secret(value):
                        continue
                    confidence, tag_suffix = _compose_demotion([
                        (has_suppress_comment, "author-suppressed"),
                        (_has_fake_marker(value), "fake-marker"),
                        (is_test_path, "test-path"),
                    ])
                    detail = f"A {what} appears as a literal in tracked source."
                    if is_test_path:
                        detail += (
                            " The file sits at a test-fixture path (tests/, "
                            "fixtures/, ...) -- likely, but not provably, a mock/"
                            "throwaway credential; confidence is demoted rather than "
                            "the finding dropped. A real value-shaped secret still "
                            "flags here, just at LOW confidence."
                        )
                    if has_suppress_comment:
                        detail += (
                            " The line carries an author suppress-convention comment "
                            "(e.g. `# pragma: allowlist secret`) -- in adversarial/"
                            "third-party scanning this signal is target-controlled "
                            "and cannot be trusted to fully silence a finding, so "
                            "confidence is demoted rather than the finding dropped."
                        )
                    if _has_fake_marker(value):
                        detail += (
                            " The value also contains an explicit fake/dummy/test/"
                            "placeholder/sample/demo marker -- likely, but not "
                            "provably, a test fixture; confidence is demoted rather "
                            "than the finding dropped."
                        )
                    out.append(Finding(
                        vuln_class="hardcoded-secret",
                        title=f"Hardcoded {what} in source{tag_suffix}",
                        severity=Severity.P1, confidence=confidence,
                        file=f.rel, line=i,
                        detail=detail,
                        remediation="Move to an environment variable / secret store, "
                                    "rotate the exposed value, and scrub history.",
                        snippet="<redacted secret line>",
                    ))
        # AST: NAME = "literal" where NAME looks secret and value looks
        # real. Round-2 N-vote P2-6 fix: this branch was DEAD CODE (see
        # _PLACEHOLDER's docstring above) -- now live, it gets the SAME
        # guards _scan_literals already applies: the curated placeholder
        # list may fully suppress (our own judgment); a pragma
        # suppress-comment and a fake-value-marker may only demote
        # confidence and tag the finding (round-3: NEVER continue/drop).
        if f.tree is not None:
            for node in ast.walk(f.tree):
                if isinstance(node, ast.Assign):
                    val = node.value
                    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
                        continue
                    value = val.value.strip()
                    if _is_known_placeholder_secret(value):
                        continue
                    if _PLACEHOLDER.fullmatch(value) or len(value) < 8:
                        continue
                    for tgt in node.targets:
                        nm = _dotted(tgt)
                        # Round-3 N-vote P1 (B2) fix: this used to call
                        # raw _SECRET_NAME.search(nm), bypassing the
                        # shared _name_looks_secret helper's word-boundary
                        # guard AND its pagination-cursor-name exclusion
                        # (OUR OWN curated name-shape judgment, same
                        # "may fully exclude" category as the placeholder
                        # list -- not a target-controlled signal). 14 of
                        # awslabs/mcp's 209 revived-branch findings were
                        # pagination-named assignments
                        # (`expected_response.next_token = '...'`) that
                        # should never have reached this branch at all.
                        if not (nm and _name_looks_secret(nm)):
                            continue
                        has_suppress_comment = bool(_SUPPRESS_COMMENT.search(f.line_at(node.lineno)))
                        confidence, tag_suffix = _compose_demotion([
                            (has_suppress_comment, "author-suppressed"),
                            (_has_fake_marker(value), "fake-marker"),
                            (is_test_path, "test-path"),
                        ])
                        detail = (
                            f"'{nm}' is assigned a non-placeholder string literal; "
                            "likely a committed credential."
                        )
                        if is_test_path:
                            detail += (
                                " The file sits at a test-fixture path (tests/, "
                                "fixtures/, ...) -- this specific revived AST-assignment "
                                "branch is a known noise source on test-heavy repos "
                                "(mock/test credential assignments), so confidence is "
                                "demoted rather than the finding dropped."
                            )
                        if has_suppress_comment:
                            detail += (
                                " The line carries an author suppress-convention "
                                "comment, which in adversarial/third-party scanning "
                                "cannot be trusted to fully silence a finding -- "
                                "confidence demoted instead."
                            )
                        if _has_fake_marker(value):
                            detail += (
                                " The value also contains an explicit fake/dummy/"
                                "test/placeholder/sample/demo marker -- likely, but "
                                "not provably, a test fixture; confidence demoted "
                                "rather than the finding dropped."
                            )
                        out.append(Finding(
                            vuln_class="hardcoded-secret",
                            title=f"Hardcoded secret assigned to '{nm}'{tag_suffix}",
                            severity=Severity.P1,
                            confidence=(
                                confidence if confidence == Confidence.LOW
                                else Confidence.MEDIUM
                            ),
                            file=f.rel, line=node.lineno,
                            detail=detail,
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
