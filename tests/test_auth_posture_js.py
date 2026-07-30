"""auth-posture on JS/TS (2026-07-30 recall slice 2).

``AuthPostureDetector.run`` opened its file loop with ``if f.tree is None:
continue`` (``auth_posture.py:35``), so it never ran on a ``.ts`` file at all.
Its bind check additionally keyed on the literal ``_BIND_ALL = "0.0.0.0"``
(``:18``) -- and Express's ``app.listen(port)`` binds every interface without
containing that string anywhere.

The 2026-07-30 five-target hand audit found the consequence.
``airtable-mcp-server`` ``src/main.ts:35-57`` serves ``POST /mcp`` over
``app.listen(port, callback)`` -- all interfaces, no auth, no Origin
validation, no DNS-rebinding protection -- granting full read/write on the
operator's Airtable account through the server's own PAT.  The scanner owns a
detector for exactly that class and had it switched off on the language.

SEPARATION OF CONCERNS, deliberate (the point of the slice): only the checks
that are genuinely TEXT-shaped are un-gated.  ``debug=True`` (Werkzeug's
interactive debugger) and the mutating-route decorator walk are Python-AST
concepts with no JS analogue and stay Python-only -- faking them would be a
worse defect than the gap.
"""
import tempfile
from pathlib import Path

from mcp_scanner.detectors.auth_posture import AuthPostureDetector
from mcp_scanner.scanner import build_context


def _findings(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as d:
        for rel, body in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        ctx, _ = build_context(d)
        return AuthPostureDetector().run(ctx)


def _classes(findings, vuln_class):
    return [f for f in findings if f.vuln_class == vuln_class]


# The real shape from airtable-mcp-server src/main.ts:35-57, reduced.
AIRTABLE_MAIN_TS = """import express from 'express';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';

const app = express();
app.use(express.json({limit: '20mb'}));

app.post('/mcp', async (req, res) => {
\tconst server = createServer({airtableService});
\tconst httpTransport = new StreamableHTTPServerTransport({
\t\tsessionIdGenerator: undefined,
\t\tenableJsonResponse: true,
\t});
\tawait server.connect(httpTransport);
\tawait httpTransport.handleRequest(req, res, req.body);
});

const port = parseInt(process.env.PORT || '3000', 10);
const httpServer = app.listen(port, () => {
\tconsole.error(`Airtable MCP server running on http://localhost:${port}/mcp`);
\tconsole.error('WARNING: HTTP transport has no authentication. Only use behind a reverse proxy or in a secured setup.');
});
"""


# --------------------------------------------------------------------- #
# The ground truth this slice exists for
# --------------------------------------------------------------------- #
def test_express_listen_with_no_host_is_flagged():
    """``app.listen(port, callback)``: the second argument is a CALLBACK, not
    a host, so Node binds every interface.  No ``0.0.0.0`` string appears
    anywhere in the file -- which is precisely why the literal-keyed check
    missed it."""
    out = _classes(_findings({"src/main.ts": AIRTABLE_MAIN_TS}), "network-exposure")
    assert len(out) == 1, f"expected exactly one bind finding, got {out}"
    assert out[0].file == "src/main.ts"
    assert out[0].line == 18


def test_bind_finding_is_not_silenced_by_the_word_auth_in_a_string():
    """The file's own console message contains the word 'authentication'.
    ``_AUTH_HINTS`` is a file-wide substring test over raw text, so reusing it
    unchanged would let a log line that WARNS about missing auth count as
    evidence that auth exists -- the prose-matching defect the audit found in
    ``has_containment``/``has_allowlist``.  String and comment text must be
    stripped before any auth-hint judgement."""
    out = _classes(_findings({"src/main.ts": AIRTABLE_MAIN_TS}), "network-exposure")
    assert out, "the finding must survive the word 'authentication' in a string literal"
    assert "no authentication" in out[0].detail.lower() or "unauthenticated" in out[0].detail.lower()


# --------------------------------------------------------------------- #
# Scope: what must NOT be flagged
# --------------------------------------------------------------------- #
def test_listen_with_an_explicit_loopback_host_is_not_flagged():
    src = "const app = express();\napp.listen(port, '127.0.0.1', () => {});\n"
    assert _classes(_findings({"src/server.ts": src}), "network-exposure") == []


def test_listen_with_a_host_variable_is_not_flagged():
    """A non-literal host argument is UNKNOWN, not all-interfaces.  Flagging
    it would be a guess in the over-claiming direction."""
    src = "const host = process.env.HOST;\napp.listen(port, host, () => {});\n"
    assert _classes(_findings({"src/server.ts": src}), "network-exposure") == []


def test_listen_with_an_options_object_host_is_not_flagged():
    src = "server.listen({ port: 3000, host: '127.0.0.1' });\n"
    assert _classes(_findings({"src/server.ts": src}), "network-exposure") == []


def test_listen_inside_a_comment_is_not_flagged():
    src = "// app.listen(port);\n/* server.listen(8080) */\n"
    assert _classes(_findings({"src/server.ts": src}), "network-exposure") == []


def test_addeventlistener_is_not_a_network_bind():
    """``.listen(`` must not match ``addEventListener(`` or any other method
    that merely ends in those characters."""
    src = "el.addEventListener('click', handler);\nemitter.listeners('x');\n"
    assert _classes(_findings({"src/ui.ts": src}), "network-exposure") == []


# --------------------------------------------------------------------- #
# The 0.0.0.0 literal, now recognised on JS/TS too
# --------------------------------------------------------------------- #
def test_explicit_bind_all_literal_in_ts_is_flagged():
    src = "app.listen(port, '0.0.0.0', () => {});\n"
    out = _classes(_findings({"src/server.ts": src}), "network-exposure")
    assert len(out) == 1
    assert "0.0.0.0" in out[0].title


def test_bind_all_inside_a_prose_string_is_not_a_bind():
    """notion-mcp-server's own warning text -- "WARNING: unauthenticated HTTP
    is bound to 0.0.0.0. Prefer the default 127.0.0.1 loopback binding..." --
    appears verbatim in four places in its test file.  A message ABOUT the
    risk is not the risk.  The literal counts only when it is the entire
    string value."""
    src = (
        "const warnings = ['WARNING: unauthenticated HTTP is bound to 0.0.0.0. "
        "Prefer the default 127.0.0.1 loopback binding.'];\n"
    )
    assert _classes(_findings({"src/warn.ts": src}), "network-exposure") == []


def test_bind_all_comparison_is_not_a_bind():
    """``if (host === '0.0.0.0') return '127.0.0.1'`` is a display helper that
    rewrites the value TO loopback.  Checking for a value is the opposite of
    setting it (notion-mcp-server ``scripts/server-options.ts:167``)."""
    src = (
        "function displayHostForBinding(host: string): string {\n"
        "  if (host === '0.0.0.0') {\n"
        "    return '127.0.0.1'\n"
        "  }\n"
        "  return host\n"
        "}\n"
    )
    assert _classes(_findings({"scripts/server-options.ts": src}), "network-exposure") == []


def test_bind_all_assignment_is_still_a_bind():
    """The narrowing above must not silence a real conditional all-interfaces
    host assignment (firecrawl-mcp-server ``src/index.ts:2905``)."""
    src = (
        "const HOST =\n"
        "  process.env.CLOUD_SERVICE === 'true'\n"
        "    ? '0.0.0.0'\n"
        "    : process.env.HOST || 'localhost';\n"
    )
    out = _classes(_findings({"src/index.ts": src}), "network-exposure")
    assert len(out) == 1 and out[0].line == 3


def test_bind_all_literal_and_hostless_listen_do_not_double_report():
    """One bind site is one finding.  The explicit-literal path and the
    missing-host path must not both fire on the same line."""
    src = "app.listen(port, '0.0.0.0', () => {});\n"
    assert len(_classes(_findings({"src/server.ts": src}), "network-exposure")) == 1


# --------------------------------------------------------------------- #
# Python-only checks stay Python-only
# --------------------------------------------------------------------- #
def test_debug_true_check_is_not_faked_on_js():
    """``debug: true`` in a JS options object is not Werkzeug's interactive
    debugger, and the P1 detail ("an unhandled exception yields remote code
    execution") would be simply false.  Python-AST concept, stays Python."""
    src = "app.listen(port);\nconst opts = { debug: true };\n"
    assert _classes(_findings({"src/server.ts": src}), "debug-console") == []


def test_mutating_route_check_is_not_faked_on_js():
    """The mutating-route walk reads Python decorators and a Python function
    signature (``Depends``/``Security``).  There is no JS analogue that means
    the same thing, so it is not extrapolated."""
    src = "app.post('/mcp', async (req, res) => { await mutate(req.body); });\n"
    assert _classes(_findings({"src/server.ts": src}), "missing-auth") == []


def test_python_bind_all_behaviour_is_unchanged():
    src = 'import flask\napp = flask.Flask(__name__)\napp.run(host="0.0.0.0")\n'
    out = _classes(_findings({"app.py": src}), "network-exposure")
    assert len(out) == 1
    assert out[0].severity.value == "P2"


# --------------------------------------------------------------------- #
# Repo-level rate-limit check now sees JS binds too
# --------------------------------------------------------------------- #
def test_rate_limit_check_sees_a_js_only_network_bind():
    """``repo_binds_network`` was only ever set by a Python file, so a JS-only
    server never reached the rate-limiter check at all."""
    out = _classes(_findings({"src/server.ts": "app.listen(port);\n"}), "no-rate-limit")
    assert len(out) == 1


def test_rate_limit_check_credits_a_js_rate_limiter():
    files = {
        "src/server.ts": "import rateLimit from 'express-rate-limit';\n"
                         "app.use(rateLimit({windowMs: 60000, max: 100}));\n"
                         "app.listen(port);\n",
    }
    assert _classes(_findings(files), "no-rate-limit") == []


def test_rate_limit_hint_in_a_js_comment_does_not_count():
    """A hint found only in prose is not a rate limiter.  Same
    strip-before-judging rule as the auth hint above."""
    files = {"src/server.ts": "// TODO: add a rate_limit here\napp.listen(port);\n"}
    assert len(_classes(_findings(files), "no-rate-limit")) == 1
