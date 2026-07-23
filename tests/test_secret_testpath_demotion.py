"""Wave-4 FP class: test-path confidence demotion for hardcoded-secret findings.

Reviving the AST-assignment hardcoded-secret branch (round-2 P2-6) surfaced a
large new noise class on test-heavy repos: one real-world ecosystem clone went
from 5 to ~196-209 `hardcoded-secret` findings, almost entirely mock/test
credential assignments in test files (`mock_credentials.token = "..."`,
`provider._password = "test..."`). Wave 4 demotes those to LOW + a `(test-path)`
tag rather than dropping them.

WAVE-4 ROUND-2 SAFETY FIX (refuter-B P1, 2026-07-23)
----------------------------------------------------
The first cut demoted on the bare test-fixture PATH alone. But a path name is
TARGET-CONTROLLABLE and discriminates nothing real: `fixtures/`, `spec/`,
`mocks/`, `testserver/`, `testdata/` are all production-plausible (Django/Rails
`fixtures/` seed prod DBs; `spec/` holds OpenAPI/protobuf specs; `mocks/` ships
as a runtime MSW feature; Go's `testdata/` VCR cassettes have contained REAL
recorded prod credentials). A genuine value-shaped secret (AKIA/ghp_/sk-/JWT/
private-key-block) dropped to LOW on a path segment alone -- weaker than the
cert-path precedent, which required MULTIPLE independent corroborating signals
(self-signed AND test-path AND CN/SAN marker).

THE INVARIANT this file pins: a genuine value-shaped secret sitting in ANY
directory RETAINS its base confidence (HIGH for the value-shape branch, MEDIUM
for the AST-name branch) unless there is a CORROBORATING signal BEYOND the bare
path. `test-path` is now a PAIR-ONLY signal: it demotes only when composed with
a standalone demoter (author-suppressed / fake-marker-in-value) or, for the
AST-name branch, a mock/fake-shaped assignment NAME. It never demotes on its
own. Nothing is ever suppressed/dropped -- a real secret on a test path still
flags, just at its base (undemoted) confidence when no corroboration exists.

THE ONE LAW (module-wide) still holds: full suppression is reserved for OUR OWN
curated exact-match judgment; every other signal may only demote confidence and
tag the finding.

These fixtures are constructed in-memory (SourceFile/RepoContext built directly)
so the assertions pin the detector's OWN confidence output, isolated from the
reachability/taint post-passes that scan_repo layers on afterward.
"""
import ast
from pathlib import Path

import pytest

from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.base import RepoContext, SourceFile
from mcp_scanner.models import Confidence


def _run(rel: str, text: str):
    """Run the secret-handling detector over a single in-memory .py file at
    repo-relative path ``rel`` and return only the hardcoded-secret findings."""
    tree = ast.parse(text)
    sf = SourceFile(
        path=Path(rel), rel=rel, text=text, tree=tree, lines=text.splitlines()
    )
    ctx = RepoContext(root=Path("."), files=[sf], tracked=set(), is_git=False)
    findings = SecretHandlingDetector().run(ctx)
    return [f for f in findings if f.vuln_class == "hardcoded-secret"]


# --- (1) mock/test-named assignment under tests/ demotes to LOW + tag --------
# The noise class wave-4 targets. The assignment NAME is mock-shaped AND the
# file is a test path -> two corroborating signals -> demote. Its value is NOT
# value-shaped, so only the AST-NAME branch fires.

def test_mock_named_assignment_under_tests_demotes_to_low_test_path():
    src = 'mock_credentials.token = "aVeryLongLookingCredential1234567890"\n'
    hits = _run("tests/test_auth.py", src)
    assert hits, "a mock-named secret assignment under tests/ must still emit a finding, never zero"
    assert all(f.confidence == Confidence.LOW for f in hits), (
        f"mock-name + test-path must demote to LOW, got {[f.confidence for f in hits]}"
    )
    assert all("test-path" in f.title for f in hits), (
        f"demoted finding must be tagged (test-path), got {[f.title for f in hits]}"
    )
    assert all("mock-name" in f.title for f in hits), (
        f"the corroborating mock-name signal must be tagged too, got {[f.title for f in hits]}"
    )


def test_mock_named_assignment_under_testdata_demotes():
    # Noise reduction survives on a PROD-PLAUSIBLE segment too, because the
    # mock NAME (not the path) is what licenses the demotion.
    src = 'fake_provider._password = "some_long_test_value_9876543210"\n'
    hits = _run("testdata/cassettes.py", src)
    assert hits, "mock-named assignment under testdata/ must still flag"
    assert all(f.confidence == Confidence.LOW for f in hits)
    assert all("test-path" in f.title and "mock-name" in f.title for f in hits)


def test_same_named_assignment_outside_tests_is_unchanged_medium():
    # A mock-shaped NAME alone (no test path) is NOT sufficient to demote -- a
    # co-signal without the path stays at base MEDIUM, no tag.
    src = 'mock_credentials.token = "aVeryLongLookingCredential1234567890"\n'
    hits = _run("src/server/auth.py", src)
    assert hits, "the same assignment outside tests/ must still flag"
    assert all(f.confidence == Confidence.MEDIUM for f in hits), (
        f"outside a test path the AST-name finding stays MEDIUM, got {[f.confidence for f in hits]}"
    )
    assert all("test-path" not in f.title for f in hits)


def test_plain_secret_named_assignment_under_tests_is_NOT_demoted_on_path_alone():
    # A secret-NAMED (not mock-named) AST assignment with a non-value-shaped
    # value, under tests/, with NO mock name and NO fake value: the bare path
    # must NOT demote it. Stays MEDIUM (base for the AST branch).
    src = 'api_key = "aVeryLongLookingCredential1234567890"\n'
    hits = _run("tests/test_client.py", src)
    assert hits, "a secret-named assignment under tests/ must still flag"
    assert all(f.confidence == Confidence.MEDIUM for f in hits), (
        f"bare test-path must NOT demote a non-mock, non-fake AST finding, got "
        f"{[f.confidence for f in hits]}"
    )
    assert all("test-path" not in f.title for f in hits)


# --- (2) THE HARD INVARIANT: a real VALUE-SHAPED secret with NO other signal -
# retains base (HIGH) confidence in ANY directory, including test paths and the
# production-plausible segments refuter-B flagged. It still FLAGS (never
# suppressed); it is just not demoted on path alone.

PROD_PLAUSIBLE_DIRS = ["fixtures", "spec", "mocks", "testserver", "testdata"]
UNAMBIGUOUS_TEST_DIRS = ["tests", "test", "__tests__"]


@pytest.mark.parametrize("d", PROD_PLAUSIBLE_DIRS + UNAMBIGUOUS_TEST_DIRS)
def test_real_akia_value_in_any_dir_stays_high_not_demoted_on_path_alone(d):
    # refuter-B's 5 prod-plausible repros (+ the unambiguous test dirs, which
    # the invariant ALSO covers): a real AKIA with no corroborating signal must
    # keep base HIGH confidence, never LOW, never a test-path tag.
    src = 'AWS = "AKIA1234567890ABCDEF"\n'
    hits = _run(f"{d}/creds.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, f"a real AKIA under {d}/ MUST still flag -- never suppressed"
    assert all(f.confidence == Confidence.HIGH for f in aws), (
        f"a real value-shaped secret under {d}/ with NO corroborating signal must "
        f"retain base HIGH confidence, got {[f.confidence for f in aws]}"
    )
    assert all("test-path" not in f.title for f in aws), (
        f"bare path must not tag/demote a value-shaped secret, got {[f.title for f in aws]}"
    )


@pytest.mark.parametrize("d", PROD_PLAUSIBLE_DIRS)
def test_real_ghp_value_in_prod_plausible_dir_stays_high(d):
    src = 'GH = "ghp_' + "A" * 36 + '"\n'
    hits = _run(f"{d}/creds.py", src)
    ghp = [f for f in hits if "GitHub" in f.title]
    assert ghp, f"a real ghp_ token under {d}/ MUST still flag"
    assert all(f.confidence == Confidence.HIGH for f in ghp), (
        f"a real ghp_ token under {d}/ must retain base HIGH, got {[f.confidence for f in ghp]}"
    )
    assert all("test-path" not in f.title for f in ghp)


def test_real_private_key_block_in_fixtures_stays_high():
    src = 'KEY = "-----BEGIN PRIVATE KEY-----MIIabc123-----END PRIVATE KEY-----"\n'
    hits = _run("fixtures/key_material.py", src)
    pk = [f for f in hits if "private key" in f.title]
    assert pk, "a real private-key block under fixtures/ MUST still flag"
    assert all(f.confidence == Confidence.HIGH for f in pk), (
        f"a real private-key block must retain base HIGH, got {[f.confidence for f in pk]}"
    )
    assert all("test-path" not in f.title for f in pk)


def test_real_akia_value_outside_tests_confidence_unchanged():
    src = 'API_KEY = "AKIA1234567890ABCDEF"\n'
    hits = _run("src/config.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, "a real AKIA value outside tests/ must flag"
    assert all(f.confidence == Confidence.HIGH for f in aws)
    assert all("test-path" not in f.title for f in aws)


# --- (3) noise reduction that DOES survive: fake-VALUED value-shape secrets ---
# A value that is self-evidently fake (contains an xxxx/fake/example marker as a
# whole word) CANNOT be a working credential, so fake-marker is a safe
# standalone demoter -- and test-path then composes as an accurate tag.

def test_fake_valued_akia_shape_in_tests_demotes_via_fake_marker():
    # AKIAXXXXXXXXXXXXXXXX matches the AKIA value shape AND carries the xxxx
    # fake marker -> demotes on fake-marker (self-limiting), test-path tags.
    src = 'k = "AKIAXXXXXXXXXXXXXXXX"\n'
    hits = _run("tests/test_client.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, "an AKIA-shaped fake value must still flag"
    assert all(f.confidence == Confidence.LOW for f in aws), (
        f"a fake-valued AKIA shape demotes via fake-marker, got {[f.confidence for f in aws]}"
    )
    assert any("fake-marker" in f.title and "test-path" in f.title for f in aws), (
        f"fake-marker and test-path must compose, got {[f.title for f in aws]}"
    )


def test_fake_valued_secret_outside_tests_still_demotes_via_fake_marker_no_pathtag():
    # fake-marker demotes on ANY path (it is self-limiting); with no test path
    # there is simply no test-path tag.
    src = 'k = "AKIAXXXXXXXXXXXXXXXX"\n'
    hits = _run("src/config.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws
    assert all(f.confidence == Confidence.LOW for f in aws)
    assert all("fake-marker" in f.title for f in aws)
    assert all("test-path" not in f.title for f in aws)


# --- (4) interaction: test-path composes with fake-marker / pragma -----------

def test_testpath_composes_with_fake_marker_still_visible():
    src = 'token = "fake_test_credential_value_1234"\n'
    hits = _run("tests/test_creds.py", src)
    assert hits, "test-path + fake-marker must still emit a finding, never zero"
    assert all(f.confidence == Confidence.LOW for f in hits)
    assert any("fake-marker" in f.title and "test-path" in f.title for f in hits), (
        f"both demotion tags must compose into the title, got {[f.title for f in hits]}"
    )


def test_testpath_composes_with_pragma_never_suppressed():
    # A REAL value-shaped secret on a test path WITH an author pragma: the
    # pragma is a standalone (author) demoter; test-path composes as a tag.
    # Still visible, LOW, both tags present.
    src = 'bad = "AKIA1234567890ABCDEF"  # pragma: allowlist secret\n'
    hits = _run("tests/test_leak.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, "test-path + pragma on a REAL secret must NEVER fully suppress -- must still flag"
    assert all(f.confidence == Confidence.LOW for f in aws)
    assert any("author-suppressed" in f.title and "test-path" in f.title for f in aws), (
        f"both author-suppressed and test-path tags must compose, got {[f.title for f in aws]}"
    )


def test_real_akia_on_test_path_without_pragma_stays_high():
    # Same AKIA as above but WITHOUT the pragma: no standalone demoter, no
    # co-signal -> stays HIGH even though the pragma-bearing sibling demoted.
    src = 'bad = "AKIA1234567890ABCDEF"\n'
    hits = _run("tests/test_leak.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws
    assert all(f.confidence == Confidence.HIGH for f in aws), (
        f"a bare AKIA on a test path (no pragma, no fake marker) stays HIGH, got "
        f"{[f.confidence for f in aws]}"
    )
