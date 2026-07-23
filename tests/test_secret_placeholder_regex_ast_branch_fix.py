"""Round-2 N-vote P2-6 fix: ``_PLACEHOLDER``'s regex (secret_handling.py)
contained an empty alternative in its top-level group
(``r"^(|x+|your..."``), so ``.match()`` was ALWAYS truthy at position 0 --
the entire AST ``NAME = "literal"`` hardcoded-secret-assignment branch has
been silently dead since 2026-07-13. This falsified wave-1's own
"proven cannot-mask-a-real-secret" claims, since the flagship placeholder
test (``clean_secret_placeholder``) was passing for the wrong reason (the
branch never ran at all, not because the curated placeholder correctly
suppressed it).

Fixed: anchored full-match (no empty alternative), ``_is_known_placeholder_
secret`` wired in properly (so the curated placeholder list still
suppresses via this path), and the same pragma-demotes-confidence
(never-fully-suppresses) convention from P0-3 applied here too."""
import ast
from pathlib import Path

from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.base import RepoContext, SourceFile
from mcp_scanner.detectors.secret_handling import _PLACEHOLDER
from mcp_scanner.models import Confidence


def _scan_src(src: str):
    tree = ast.parse(src)
    f = SourceFile(path=Path("x.py"), rel="x.py", text=src, tree=tree, lines=src.splitlines())
    ctx = RepoContext(root=Path("."), files=[f], tracked=set(), is_git=False)
    return SecretHandlingDetector().run(ctx)


def test_real_secret_shaped_assignment_flags_via_ast_branch():
    # The exact repro shape the bug hid: a secret-named variable assigned
    # a real-looking (non-placeholder) string literal.
    src = 'SECRET_KEY = "s3cr3t_9f8a7b6c_zqxlmvwerty392847"\n'
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret" and "SECRET_KEY" in f.title]
    assert hits, "a real secret-shaped NAME = 'literal' assignment must flag via the AST branch"
    assert hits[0].confidence == Confidence.MEDIUM


def test_known_placeholder_value_still_suppressed_via_ast_branch():
    # The curated placeholder list must suppress via THIS branch too, not
    # just the line-based _scan_literals path.
    src = "DUMMY_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret" and "DUMMY_SECRET_KEY" in f.title]
    assert hits == [], f"the curated AWS placeholder must still suppress via the AST branch, got {hits}"


def test_pragma_on_ast_branch_demotes_not_suppresses():
    # Same adversarial-mode philosophy as P0-3: a pragma comment on a REAL
    # secret assignment must demote confidence, never fully vanish.
    src = 'SECRET_KEY = "s3cr3t_9f8a7b6c_zqxlmvwerty392847"  # pragma: allowlist secret\n'
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret" and "SECRET_KEY" in f.title]
    assert hits, "pragma must never fully suppress a real secret assignment"
    assert hits[0].confidence == Confidence.LOW


def test_placeholder_words_still_excluded_as_whole_values():
    for value in ("changeme", "placeholder", "example", "dummy", "test", "none", "null", "xxxxxxxx"):
        src = f'API_TOKEN = "{value}"\n'
        findings = _scan_src(src)
        hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
        assert hits == [], f"whole-value placeholder word '{value}' must not flag, got {hits}"


def test_placeholder_word_as_prefix_of_real_value_no_longer_falsely_excluded():
    # Precision fix: the OLD .match() (partial, start-anchored) would have
    # treated any value STARTING with "test" as a placeholder. A real
    # secret merely starting with a placeholder-ish word must still flag.
    src = 'API_TOKEN = "testing_actually_a_real_leaked_credential_9f8a"\n'
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a value merely starting with a placeholder word (not equal to it) must still flag"


def test_obviously_fake_named_test_fixture_not_flagged():
    # Live fleet-sweep catch (this branch was dead code before this fix,
    # so it had never been sweep-tested): discord-mcp's OWN test fixture,
    # `TEST_TOKEN = "fake-test-token-do-not-use"` -- obviously fake by its
    # own literal value text.
    src = 'TEST_TOKEN = "fake-test-token-do-not-use"\n'
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits == [], f"an obviously-fake test-fixture value must not flag, got {hits}"


def test_placeholder_regex_has_no_empty_alternative():
    # Direct regression guard on the bug itself: an empty string must
    # NEVER satisfy this pattern via a trivial zero-width alternative.
    assert _PLACEHOLDER.fullmatch("totally_not_a_placeholder_value_123") is None
