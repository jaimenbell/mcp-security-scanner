"""What is LOGGED is the terminal of a member chain, not its root object.

FROM THE 2026-07-29 HELD-OUT MEASUREMENT, class (v). neon
`app/api/[transport]/route.ts:958`:

    logger.info('OAuth token found', { clientId: token.client.id });

What reaches the log is an OAuth **client id** -- public by design. The
detector fired because, after string-literal contents are stripped, `_IDENT`
tokenizes the remaining code into `clientId, token, client, id` and checks each
one independently, so the ROOT object's name (`token`) matched even though no
secret-shaped value is logged.

THE RULE: for a member chain, judge the TERMINAL segment -- that is the value
that gets logged. `token.client.id` -> `id`, not secret. `config.apiKey` ->
`apiKey`, secret. A bare identifier is its own terminal, so `logger.info(token)`
is unaffected.

WITH ONE CURATED RECOVERY, because a naive terminal-only rule would go blind to
a real leak: when the terminal is a GENERIC VALUE ACCESSOR (`value`, `raw`,
`plain`, `text`, `contents`, ...) it carries no information of its own, so the
parent segment is judged instead. `secret.value` and `token.raw` still fire;
`token.client.id` does not, because `id` is not a value accessor.

APPLIED TO BOTH SURFACES IN ONE COMMIT. The identical bug existed in the Python
AST path (`_arg_mentions_secret` walked every Name/Attribute in the argument
and matched any of them). Fixing only the measured surface is how a rule ends
up implemented in some detectors and not the rest, which is worse than not
having it -- so both paths share one decision helper and both are pinned here.
"""
import ast
from pathlib import Path

import pytest

from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.base import RepoContext, SourceFile


def _logs(rel: str, text: str):
    tree = ast.parse(text) if rel.endswith(".py") else None
    sf = SourceFile(path=Path(rel), rel=rel, text=text, tree=tree,
                    lines=text.splitlines())
    ctx = RepoContext(root=Path("."), files=[sf], tracked=set(), is_git=False)
    return [f for f in SecretHandlingDetector().run(ctx)
            if f.vuln_class == "secret-in-log"]


def _js(line):
    return _logs("app/route.ts", line + "\n")


def _py(line):
    return _logs("app/route.py", "import logging\nlogger = logging.getLogger(__name__)\n" + line + "\n")


# --- the measured false positive ------------------------------------------
def test_the_measured_neon_line_is_silent():
    assert _js("logger.info('OAuth token found', { clientId: token.client.id });") == []


@pytest.mark.parametrize("line", [
    "logger.info('found', { clientId: token.client.id });",
    "console.log(session.token.id);",
    "logger.debug('x', { len: apiKey.length });",
    "logger.info(token.expiresAt);",
    "console.log(credentials.token.createdAt);",
])
def test_js_member_chain_terminal_decides(line):
    assert _js(line) == [], (
        f"{line!r} logs a non-secret terminal of a chain whose ROOT happens to "
        "be secret-named"
    )


@pytest.mark.parametrize("line", [
    "logger.info('found', {'client_id': token.client.id})",
    "print(session.token.id)",
    "logger.info(token.expires_at)",
])
def test_python_member_chain_terminal_decides(line):
    assert _py(line) == [], f"{line!r} logs a non-secret terminal"


def test_a_call_wrapping_a_secret_still_fires_on_both_surfaces():
    """STATED CONSERVATIVE OUTCOME, not an oversight. Both paths recurse INTO
    call arguments, so `len(api_key)` / `String(apiKey)` still fire even though
    only a length is logged. Deciding otherwise would mean trusting an
    arbitrary wrapper function to be non-leaking, which is the same
    target-controlled trust the redaction-wrapper case below refuses. The
    conservative direction is the correct one here, and it is asserted rather
    than left to be rediscovered."""
    assert len(_py("logger.debug('x', extra={'n': len(api_key)})")) == 1
    assert len(_js("logger.debug('x', { n: String(apiKey).length });")) == 1


# --- the recall half ------------------------------------------------------
@pytest.mark.parametrize("line", [
    "logger.info(token);",
    "console.log(config.apiKey);",
    "logger.error(`bad ${apiKey}`);",
    "console.log(user.client_secret);",
    "logger.warn(opts.password);",
])
def test_js_real_secret_logging_still_flags(line):
    assert len(_js(line)) == 1, f"{line!r} logs a secret-shaped terminal"


@pytest.mark.parametrize("line", [
    "logger.info(token)",
    "print(config.api_key)",
    "logger.error(f'bad {api_key}')",
    "print(user.client_secret)",
])
def test_python_real_secret_logging_still_flags(line):
    assert len(_py(line)) == 1, f"{line!r} logs a secret-shaped terminal"


# --- the curated generic-accessor recovery --------------------------------
@pytest.mark.parametrize("line", [
    "console.log(secret.value);",
    "logger.info(token.raw);",
    "console.log(password.plain);",
    "logger.debug(apiKey.text);",
])
def test_js_generic_value_accessor_falls_back_to_the_parent(line):
    assert len(_js(line)) == 1, (
        f"{line!r}: a generic value accessor carries no information of its "
        "own, so the parent segment must be judged instead"
    )


@pytest.mark.parametrize("line", [
    "print(secret.value)",
    "logger.info(token.raw)",
])
def test_python_generic_value_accessor_falls_back_to_the_parent(line):
    assert len(_py(line)) == 1


def test_id_is_not_treated_as_a_generic_value_accessor():
    """The distinction the whole fix turns on. If `id` were in the accessor
    list, the measured neon line would fire again -- asserted directly rather
    than left implicit in the list's contents."""
    from mcp_scanner.detectors.secret_handling import _GENERIC_VALUE_ACCESSORS

    assert "id" not in _GENERIC_VALUE_ACCESSORS
    assert "value" in _GENERIC_VALUE_ACCESSORS


# --- redaction-wrapper context (declined as a suppressor, kept as a note) --
def test_redaction_wrapper_is_noted_as_context_but_never_suppresses():
    """notion `scripts/start-server.ts:150` wraps the logged token in
    `redactToken(...)`. A wrapper NAME is target-controlled -- a hostile repo
    could call a passthrough `redactToken` -- so per README's one law it may
    not silence the finding. It IS surfaced as context so a triager can check
    the helper instead of re-deriving it."""
    hits = _js("console.log(`session with token ${redactToken(resolution.token)}`);")
    assert len(hits) == 1, "must NOT be suppressed on a target-controlled name"
    assert "redactToken" in hits[0].detail
    assert "not verified" in hits[0].detail.lower()
