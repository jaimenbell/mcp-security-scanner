"""Wave-4 FP class: test-path confidence demotion for hardcoded-secret findings.

Reviving the AST-assignment hardcoded-secret branch (round-2 P2-6) surfaced a
large new noise class on test-heavy repos: one real-world ecosystem clone went
from 5 to ~196-209 `hardcoded-secret` findings, almost entirely mock/test
credential assignments in test files (`mock_credentials.token = "..."`,
`provider._password = "test..."`). This mirrors the cert/pragma/fake-marker
demotion pattern already established in this module: a hardcoded-secret finding
whose file sits at a test-fixture path DEMOTES to LOW confidence and is tagged
`(test-path)` -- it is NEVER dropped/continue'd/suppressed.

THE ONE LAW (module-wide): full suppression is reserved for OUR OWN curated
exact-match judgment. Test-path is one more demotion signal, composed via the
established `_compose_demotion` path -- it demotes CONFIDENCE, it does not make
a real, value-shaped secret vanish just because it lives under `tests/`. The
value-shape backstop from fp-wave1 (AKIA.../ghp_.../-----BEGIN PRIVATE KEY-----)
MUST still flag (LOW at worst) even on a test path.

These fixtures are constructed in-memory (SourceFile/RepoContext built directly)
so the assertions pin the detector's OWN confidence output, isolated from the
reachability/taint post-passes that scan_repo layers on afterward.
"""
import ast
from pathlib import Path

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

def test_mock_named_assignment_under_tests_demotes_to_low_test_path():
    # A test-named secret assignment (the exact wave-4 noise shape). Its value
    # is NOT value-shaped (no AKIA/ghp_/JWT/key-block), so only the AST-NAME
    # branch fires. Outside a test path this is MEDIUM; under tests/ it must
    # demote to LOW and carry the "(test-path)" tag -- never drop.
    src = 'mock_credentials.token = "aVeryLongLookingCredential1234567890"\n'
    hits = _run("tests/test_auth.py", src)
    assert hits, "a test-named secret assignment under tests/ must still emit a finding, never zero"
    assert all(f.confidence == Confidence.LOW for f in hits), (
        f"test-path assignment must demote to LOW, got {[f.confidence for f in hits]}"
    )
    assert all("test-path" in f.title for f in hits), (
        f"demoted finding must be tagged (test-path), got {[f.title for f in hits]}"
    )


def test_same_named_assignment_outside_tests_is_unchanged_medium():
    # Guard #3 (AST branch): the SAME assignment OUTSIDE a test path keeps its
    # pre-demotion confidence (MEDIUM) and carries no test-path tag -- demotion
    # is test-path-scoped.
    src = 'mock_credentials.token = "aVeryLongLookingCredential1234567890"\n'
    hits = _run("src/server/auth.py", src)
    assert hits, "the same assignment outside tests/ must still flag"
    assert all(f.confidence == Confidence.MEDIUM for f in hits), (
        f"outside a test path the AST-name finding stays MEDIUM, got {[f.confidence for f in hits]}"
    )
    assert all("test-path" not in f.title for f in hits)


# --- (2) CRITICAL: a REAL value-shaped secret under tests/ STILL flags -------

def test_real_akia_value_under_tests_still_flagged_low_not_suppressed():
    # The value-shape backstop (fp-wave1) must survive test-path demotion: a
    # genuine AWS access-key-id value under tests/ must STILL flag (LOW at
    # worst), never vanish just because it's under tests/.
    src = 'API_KEY = "AKIA1234567890ABCDEF"\n'
    hits = _run("tests/test_client.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, "a real AKIA value under tests/ MUST still flag -- the value-shape backstop must survive"
    assert all(f.confidence == Confidence.LOW for f in aws), (
        f"value-shaped secret on a test path demotes to LOW (at worst), got {[f.confidence for f in aws]}"
    )
    assert all("test-path" in f.title for f in aws)


def test_real_ghp_value_under_tests_still_flagged():
    src = 'GH_TOKEN = "ghp_' + "A" * 36 + '"\n'
    hits = _run("tests/fixtures/creds.py", src)
    ghp = [f for f in hits if "GitHub" in f.title]
    assert ghp, "a real ghp_ token under a test-fixture path MUST still flag"
    assert all(f.confidence == Confidence.LOW for f in ghp)
    assert all("test-path" in f.title for f in ghp)


def test_real_private_key_block_under_tests_still_flagged():
    src = 'KEY = "-----BEGIN PRIVATE KEY-----MIIabc123-----END PRIVATE KEY-----"\n'
    hits = _run("tests/data/key_material.py", src)
    pk = [f for f in hits if "private key" in f.title]
    assert pk, "a real private-key block under tests/ MUST still flag"
    assert all(f.confidence == Confidence.LOW for f in pk)
    assert all("test-path" in f.title for f in pk)


# --- (3) value-shape secret OUTSIDE a test path: confidence UNCHANGED --------

def test_real_akia_value_outside_tests_confidence_unchanged():
    # Guard #3 (value-shape branch): the SAME AKIA value OUTSIDE a test path
    # keeps its HIGH confidence -- test-path demotion must not leak to
    # non-test paths.
    src = 'API_KEY = "AKIA1234567890ABCDEF"\n'
    hits = _run("src/config.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, "a real AKIA value outside tests/ must flag"
    assert all(f.confidence == Confidence.HIGH for f in aws), (
        f"outside a test path the value-shape finding stays HIGH, got {[f.confidence for f in aws]}"
    )
    assert all("test-path" not in f.title for f in aws)


# --- (4) interaction: test-path composes with fake-marker / pragma -----------

def test_testpath_composes_with_fake_marker_still_visible():
    # test-path AND fake-marker both demote; the tags COMPOSE into one finding
    # (not two, not zero). Still visible, still LOW.
    src = 'token = "fake_test_credential_value_1234"\n'
    hits = _run("tests/test_creds.py", src)
    assert hits, "test-path + fake-marker must still emit a finding, never zero"
    assert all(f.confidence == Confidence.LOW for f in hits)
    assert any("fake-marker" in f.title and "test-path" in f.title for f in hits), (
        f"both demotion tags must compose into the title, got {[f.title for f in hits]}"
    )


def test_testpath_composes_with_pragma_never_suppressed():
    # A REAL value-shaped secret on a test path WITH an author pragma suppress
    # comment: the pragma is target-controlled and can never fully suppress;
    # test-path composes with it. Still visible, LOW, both tags present.
    src = 'bad = "AKIA1234567890ABCDEF"  # pragma: allowlist secret\n'
    hits = _run("tests/test_leak.py", src)
    aws = [f for f in hits if "AWS access key" in f.title]
    assert aws, "test-path + pragma on a REAL secret must NEVER fully suppress -- must still flag"
    assert all(f.confidence == Confidence.LOW for f in aws)
    assert any("author-suppressed" in f.title and "test-path" in f.title for f in aws), (
        f"both author-suppressed and test-path tags must compose, got {[f.title for f in aws]}"
    )
