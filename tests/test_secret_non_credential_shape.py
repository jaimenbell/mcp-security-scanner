"""Synthetic Bearer fixtures, and a redaction that hid their fakeness.

FROM THE 2026-07-29 HELD-OUT MEASUREMENT, class (iii): 13 of the 58 false
positives were `hardcoded-secret` P1/HIGH hits, all of them the
"Bearer-prefixed token" value pattern, all of them synthetic test fixtures:

    tests/mcp-search-profile.test.mjs   'Bearer fco_other_resource_token'
                                        'Bearer fc-primary-search-api-key'
                                        'Bearer fc-invalid-credential'
                                        'Bearer fc-telemetry-must-not-appear'
    tests/mcp-smoke.test.mjs            'Bearer fco_live_access_token'
    __tests__/proxy.test.ts             'Bearer ntn_per_request_token'

    AGGRAVATING FACTOR named in the measurement: the JSON output redacts the
    line to the literal string "<redacted secret line>", so a reader of the
    report cannot tell they are fake without opening the repo.

WHY THE EXISTING MACHINERY DID NOT CATCH THEM. All 13 already sat on paths
`_is_test_fixture_path` recognised. But `test-path` is a PAIR-ONLY signal (the
wave-4 round-2 refuter-B fix): a bare path is target-controllable and demotes
NOTHING on its own, and the value-shape branch deliberately offered no
co-signal at all, because a genuine AKIA/ghp_/sk-/JWT value must keep its base
confidence in ANY directory. That invariant is correct and is re-pinned below.

WHAT IS ADDED IS THE MISSING CO-SIGNAL, not a new suppressor. `Bearer` is by
far the weakest of the seven value patterns -- `\\bBearer\\s+[A-Za-z0-9._~+/=-]{20,}`
matches any 20+ character run, including an English word-phrase. A real bearer
token is high-entropy; `fco_other_resource_token` is four lowercase words
joined by underscores. That shape judgment is OUR OWN curated call about our
own weakest regex (same category as `_is_pagination_cursor_name`), and it is
wired as a PAIR partner so it demotes only alongside a test path -- never
alone, and never on a production path.

AND THE REDACTION IS MADE HONEST: the snippet now carries the demotion tags,
so a reader sees `<redacted secret line (non-credential-shape, test-path)>`
instead of a bare `<redacted secret line>`. The value itself is still never
printed -- a candidate secret must not be materialised into report output --
so the reader is given the REASONS rather than the string.
"""
import ast
from pathlib import Path

import pytest

from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.base import RepoContext, SourceFile
from mcp_scanner.models import Confidence


def _run(rel: str, text: str):
    tree = ast.parse(text) if rel.endswith(".py") else None
    sf = SourceFile(path=Path(rel), rel=rel, text=text, tree=tree,
                    lines=text.splitlines())
    ctx = RepoContext(root=Path("."), files=[sf], tracked=set(), is_git=False)
    return [f for f in SecretHandlingDetector().run(ctx)
            if f.vuln_class == "hardcoded-secret"]


# --- the 13 measured values, verbatim -------------------------------------
MEASURED = [
    "Bearer fco_other_resource_token",
    "Bearer fco_search_resource_token",
    "Bearer fc-primary-search-api-key",
    "Bearer fco_primary_search_resource_token",
    "Bearer fco_primary_strict_search",
    "Bearer fco_primary_search_metadata",
    "Bearer fc-companion-api-key",
    "Bearer fco_companion_search_resource_token",
    "Bearer fc-telemetry-must-not-appear",
    "Bearer fco_secondary-credential",
    "Bearer fc-invalid-credential",
    "Bearer fco_live_access_token",
    "Bearer ntn_per_request_token",
]


@pytest.mark.parametrize("value", MEASURED)
def test_word_phrase_bearer_on_a_test_path_demotes_and_is_never_dropped(value):
    hits = _run("tests/mcp-smoke.test.mjs",
                f"  headers: {{ authorization: '{value}' }},\n")
    assert len(hits) == 1, "never dropped -- the finding must still be emitted"
    f = hits[0]
    assert f.confidence is Confidence.LOW
    assert "non-credential-shape" in f.title
    assert "test-path" in f.title


@pytest.mark.parametrize("value", MEASURED)
def test_the_redaction_tells_the_reader_why_it_was_demoted(value):
    """The aggravating factor from the measurement. The snippet must not be a
    bare `<redacted secret line>` that gives a reader no way to tell a fixture
    from a live credential -- while still never printing the value itself."""
    f = _run("tests/mcp-smoke.test.mjs",
             f"  headers: {{ authorization: '{value}' }},\n")[0]
    assert "non-credential-shape" in f.snippet
    assert f.snippet != "<redacted secret line>"
    assert value not in f.snippet, (
        "a candidate secret value must never be materialised into report output"
    )


# --- the recall half, and the invariant that must not regress -------------
# Real, high-entropy bearer values. Each is deliberately placed on a TEST PATH
# -- the exact condition under which the demotion could wrongly fire -- so
# these prove the co-signal, not the path, is doing the discriminating.
@pytest.mark.parametrize("value", [
    "Bearer sk_live_51H8xKLMnOpQrStUvWxYzAb",     # mixed case + digits
    "Bearer abcdefghijklmnopqrstuvwxyz012345",     # no separators at all
    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u",
    "Bearer ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "Bearer 7f3a9c2e5b1d8f4a6c0e2b7d9f1a3c5e",     # lowercase hex, no words
])
def test_real_bearer_values_keep_base_confidence_even_under_tests(value):
    hits = _run("tests/mcp-smoke.test.mjs",
                f"  headers: {{ authorization: '{value}' }},\n")
    assert hits, "a real bearer value must still be reported"
    assert hits[0].confidence is Confidence.HIGH, (
        "wave-4 round-2 invariant (refuter-B): a genuine value-shaped secret "
        "keeps its BASE confidence in ANY directory unless a corroborating "
        f"co-signal exists -- a test path alone is not one ({value!r})"
    )


def test_word_phrase_bearer_on_a_production_path_is_not_demoted():
    """The other half of the pair rule. The shape co-signal must NOT demote on
    its own: an odd-looking bearer literal in production source keeps its base
    confidence, because a repo can legitimately hold a word-shaped credential
    and nothing here corroborates that it is fake."""
    hits = _run("src/client.ts",
                "  headers: { authorization: 'Bearer fco_live_access_token' },\n")
    assert hits
    assert hits[0].confidence is Confidence.HIGH
    assert "non-credential-shape" not in hits[0].title


@pytest.mark.parametrize("value,rel", [
    # A private-key header is uppercase words joined by '-'. It must never be
    # mistaken for a lowercase word-phrase; asserted on a test path, where a
    # wrong answer would demote it.
    ("-----BEGIN RSA PRIVATE KEY-----", "tests/fixtures/key.pem.txt"),
    ("AKIAQ7Z3K9XLMNPRSTUV", "tests/fixtures/aws.js"),
    ("xoxb-1234567890-abcdefghijklm", "tests/fixtures/slack.js"),
])
def test_the_other_six_value_patterns_are_structurally_unaffected(value, rel):
    """The shape rule is applied uniformly rather than special-cased to the
    Bearer pattern (a per-pattern carve-out is how scope drifts). It is inert
    for the other six by construction; these pin that it stays inert."""
    hits = _run(rel, f"const x = '{value}';\n")
    assert hits
    assert hits[0].confidence is Confidence.HIGH, (
        f"{value!r} is structurally credential-shaped and must not be demoted"
    )
