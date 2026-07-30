"""secret-handling's NAME-based branch on JS/TS (2026-07-30 recall slice 3).

``_scan_literals``'s name-based branch -- "NAME = <non-placeholder literal>
where NAME looks secret" -- sat under ``if f.tree is not None:``
(``secret_handling.py:975``), i.e. Python AST only.  The value-shape branch
above it already ran on raw text for every language; only the name branch was
gated.

Ground truth from the 2026-07-30 five-target hand audit:
``airtable-mcp-server`` ``src/e2e.test.ts:23`` commits a live-format Airtable
PAT.  No value pattern in ``_SECRET_VALUE_PATTERNS`` covers the ``pat...``
shape, so the value branch never saw it -- but ``_name_looks_secret(
'AIRTABLE_API_KEY')`` returns True, so the name branch would have caught it
had it been allowed to run on a ``.ts`` file.

EXPECTED GRADE: the finding lands in a test path and is graded CLI_ONLY by the
existing test-path fallback.  That is correct and desirable, not a failure --
the demotion machinery working.  What must NOT happen is the finding being
dropped, or the language being re-gated to control noise.
"""
import tempfile
from pathlib import Path

from mcp_scanner.detectors.secret_handling import SecretHandlingDetector
from mcp_scanner.models import Confidence
from mcp_scanner.scanner import build_context


def _findings(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as d:
        for rel, body in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        ctx, _ = build_context(d)
        return [f for f in SecretHandlingDetector().run(ctx)
                if f.vuln_class == "hardcoded-secret"]


# The real shape from airtable-mcp-server src/e2e.test.ts:21-23. The value is
# a synthetic look-alike of the same length/format, never the committed one.
AIRTABLE_E2E_TS = (
    "import {createServer} from './index.js';\n"
    "\n"
    "// Deliberately committed readonly PAT, scoped to a single dummy table on a personal\n"
    "// Airtable account with only public test data. Not a leaked secret.\n"
    "const AIRTABLE_API_KEY = 'patAAAAAAAAAAAAAA.0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef';\n"
)


# --------------------------------------------------------------------- #
# The ground truth this slice exists for
# --------------------------------------------------------------------- #
def test_committed_pat_in_a_ts_file_is_found():
    out = _findings({"src/e2e.test.ts": AIRTABLE_E2E_TS})
    assert len(out) == 1, f"expected the AIRTABLE_API_KEY assignment, got {out}"
    assert out[0].file == "src/e2e.test.ts"
    assert out[0].line == 5
    assert "AIRTABLE_API_KEY" in out[0].title


def test_committed_pat_value_is_never_echoed():
    """Honest redaction is unconditional -- the reasons are surfaced, the
    value never is."""
    out = _findings({"src/e2e.test.ts": AIRTABLE_E2E_TS})
    assert "patAAAA" not in out[0].snippet
    assert "patAAAA" not in out[0].detail


def test_a_bare_test_path_does_not_demote_on_its_own():
    """``e2e.test.ts`` is a test path, and ``AIRTABLE_API_KEY`` carries no
    mock/fake marker.  ``_compose_demotion`` treats test-path as a PAIR-ONLY
    signal, so with no co-signal the finding keeps its base MEDIUM -- the
    same invariant the Python branch already holds.  (A real credential does
    not become fake by living under tests/.)"""
    out = _findings({"src/e2e.test.ts": AIRTABLE_E2E_TS})
    assert out[0].confidence is Confidence.MEDIUM


# --------------------------------------------------------------------- #
# The guards that keep this from flooding
# --------------------------------------------------------------------- #
def test_placeholder_values_are_suppressed():
    src = (
        "const API_KEY = 'your_api_key_here';\n"
        "const SECRET_KEY = 'xxxxxxxxxxxx';\n"
        "const AUTH_TOKEN = '<YOUR_TOKEN>';\n"
        "const PASSWORD = 'changeme';\n"
        "const CLIENT_SECRET = process.env.CLIENT_SECRET;\n"
    )
    assert _findings({"src/config.ts": src}) == []


def test_short_values_are_suppressed():
    assert _findings({"src/a.ts": "const API_KEY = 'abc';\n"}) == []


def test_non_secret_names_are_not_flagged():
    src = (
        "const BASE_URL = 'https://api.airtable.com/v0';\n"
        "const USER_AGENT = 'airtable-mcp-server/1.14.0';\n"
        "const tokenizer_config = 'whitespace-splitting-mode';\n"
        "const nextPageToken = 'itrABCDEFGHIJKLMNOP';\n"
    )
    assert _findings({"src/const.ts": src}) == [], (
        "the word-boundary guard and the pagination-cursor exclusion in "
        "_name_looks_secret must apply on JS exactly as they do on Python"
    )


def test_mock_shaped_name_on_a_test_path_demotes_but_never_drops():
    """Two independent signals -- mock-shaped NAME plus test path -- demote to
    LOW.  Nothing is dropped: the repo's one law."""
    src = "const mock_api_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n"
    out = _findings({"src/mocks/fixtures.test.ts": src})
    assert len(out) == 1
    assert out[0].confidence is Confidence.LOW
    assert "mock-name" in out[0].title


def test_equality_comparison_is_not_an_assignment():
    """``if (apiKey === 'literal')`` sets nothing.  A regex that treats the
    ``=`` of ``===`` as an assignment would flag every credential COMPARISON
    in a repo."""
    src = (
        "if (apiKey === 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') { ok(); }\n"
        "if (secret !== 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') { no(); }\n"
    )
    assert _findings({"src/check.ts": src}) == []


def test_object_property_is_not_an_assignment():
    """The Python branch handles ``ast.Assign`` only, never a dict literal.
    The JS branch matches that scope deliberately: admitting ``{ apiKey: x }``
    would fire on every options/config object literal in a repo, and the two
    languages would stop meaning the same thing."""
    src = "const opts = { apiKey: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' };\n"
    assert _findings({"src/opts.ts": src}) == []


def test_comment_line_is_not_an_assignment():
    src = "// const API_KEY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n"
    assert _findings({"src/a.ts": src}) == []


def test_arrow_function_assignment_is_not_a_secret():
    src = "const getSecretKey = () => process.env.SECRET_KEY;\n"
    assert _findings({"src/a.ts": src}) == []


def test_member_assignment_is_flagged():
    """``this.apiKey = '...'`` is the JS analogue of the ``_dotted`` target
    the Python branch already accepts."""
    src = "class S {\n  init() {\n    this.apiKey = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n  }\n}\n"
    out = _findings({"src/s.ts": src})
    assert len(out) == 1
    assert "apiKey" in out[0].title


def test_typescript_type_annotation_does_not_block_the_match():
    src = "const API_KEY: string = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n"
    assert len(_findings({"src/a.ts": src})) == 1


# --------------------------------------------------------------------- #
# Flood control, measured on the pinned targets -- tighten the rule, never
# re-gate the language
# --------------------------------------------------------------------- #
def test_identical_assignment_repeated_in_a_file_reports_once():
    """airtable-mcp-server ``src/enhanceAirtableError.test.ts`` assigns one
    fixture value to ``apiKey`` seven times and another twice -- 17 findings
    from 9 distinct literals before this.  N copies of one literal in one file
    is ONE committed secret."""
    val = "pat1.validkey1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk"
    src = "".join(
        f"it('case {n}', () => {{\n\tconst apiKey = '{val}';\n}});\n" for n in range(7)
    )
    out = _findings({"src/enhanceAirtableError.test.ts": src})
    assert len(out) == 1, f"expected one de-duplicated finding, got {len(out)}"
    assert out[0].line == 2, "kept at the FIRST occurrence"
    assert "appears 7 times" in out[0].detail, (
        "de-duplication must state the repeat count -- it is a de-duplication, "
        "not a suppression, and the report must still say everything the 7 "
        "separate records said"
    )


def test_a_different_value_for_the_same_name_is_a_separate_finding():
    """De-duplication keys on (name, VALUE).  Two different literals assigned
    to the same variable are two different committed secrets."""
    src = (
        "const apiKey = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n"
        "const apiKey = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';\n"
    )
    assert len(_findings({"src/a.ts": src})) == 2


def test_word_phrase_value_demotes_this_branch_on_any_path():
    """notion-mcp-server ``src/openapi-mcp-server/mcp/token.ts:17``:
    ``export const NOTION_TOKEN_HEADER = 'notion-token'`` -- a header NAME, not
    a token.  This branch's only evidence is that the variable name looks
    secret, so a value that is provably a lowercase word-phrase is direct
    counter-evidence.  It is NOT in a test path, so the demotion has to stand
    on its own."""
    src = "export const NOTION_TOKEN_HEADER = 'notion-token'\n"
    out = _findings({"src/openapi-mcp-server/mcp/token.ts": src})
    assert len(out) == 1, "demoted, never dropped"
    assert out[0].confidence is Confidence.LOW
    assert "non-credential-shape" in out[0].title


def test_redaction_sentinel_is_a_placeholder():
    """mcp-server-neon ``mcp/tools/handlers/neon-auth-settings-snapshot.ts:19``:
    ``export const REDACTED_SECRET = '***redacted***'`` is the sentinel meaning
    "upstream redacted this in transit".  It cannot simultaneously be a working
    credential, which is the self-limiting bar the curated placeholder list
    requires."""
    src = "export const REDACTED_SECRET = '***redacted***' as const;\n"
    assert _findings({"mcp/tools/handlers/snapshot.ts": src}) == []


def test_redaction_placeholder_does_not_swallow_a_real_value():
    """The addition is a FULL-match on the marker word (optionally
    asterisk-wrapped).  A real credential that merely mentions it is untouched
    -- the same trap `.fullmatch()` was introduced to close for `test`."""
    src = "const API_KEY = 'redacted_but_actually_a_real_key_0123456789';\n"
    assert len(_findings({"src/a.ts": src})) == 1


def test_word_phrase_demotion_does_not_touch_the_value_shape_branch():
    """On the value-shape branch the value already matched a high-signal
    credential pattern, so the same observation stays a mere co-signal there.
    A real ``ghp_`` token keeps its base confidence outside a test path."""
    src = "const t = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';\n"
    out = _findings({"src/a.ts": src})
    assert out and out[0].confidence is not Confidence.LOW


# --------------------------------------------------------------------- #
# Python behaviour must be untouched
# --------------------------------------------------------------------- #
def test_python_name_branch_is_unchanged():
    src = "AIRTABLE_API_KEY = 'patAAAAAAAAAAAAAA.0123456789abcdef0123456789abcdef'\n"
    out = _findings({"conf.py": src})
    assert len(out) == 1
    assert "AIRTABLE_API_KEY" in out[0].title


# --------------------------------------------------------------------- #
# The invariant: one grade, two front-ends
# --------------------------------------------------------------------- #
CROSS_LANGUAGE_CASES = [
    # (name, value, expected finding count)
    ("AIRTABLE_API_KEY", "patAAAAAAAAAAAAAA.0123456789abcdef0123456789abcdef", 1),
    ("api_key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
    ("API_KEY", "your_api_key_here", 0),        # curated placeholder
    ("API_KEY", "xxxxxxxxxxxx", 0),             # curated placeholder
    ("API_KEY", "abc", 0),                      # too short
    ("BASE_URL", "https://api.example.com/v0", 0),   # name not secret-shaped
    ("nextPageToken", "itrABCDEFGHIJKLMNOP", 0),     # pagination-cursor name
    ("tokenizer_mode", "whitespace-splitting", 0),   # word-boundary guard
]


def test_name_branch_agrees_across_python_and_typescript():
    """The same (name, value) pair must produce the same number of findings,
    at the same severity and confidence, whichever language it is written in.

    This is the mechanical form of "a JS/TS finding's grade means exactly what
    a Python finding's grade means".  It is enforceable here only because both
    branches call ONE constructor -- ``_name_assignment_finding`` -- rather
    than carrying parallel implementations that drift.
    """
    for name, value, expected in CROSS_LANGUAGE_CASES:
        py = _findings({"conf.py": f"{name} = '{value}'\n"})
        ts = _findings({"src/conf.ts": f"const {name} = '{value}';\n"})
        assert len(py) == expected, f"python: {name}={value!r} -> {py}"
        assert len(ts) == expected, f"typescript: {name}={value!r} -> {ts}"
        if expected:
            assert py[0].severity is ts[0].severity
            assert py[0].confidence is ts[0].confidence
            assert py[0].title == ts[0].title
            assert py[0].detail == ts[0].detail
