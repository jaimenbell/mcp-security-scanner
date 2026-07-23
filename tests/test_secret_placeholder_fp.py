"""Wave-1 FP class 1c: widely-published placeholder credentials from SDK
example docs, and a maintainer's own suppress-convention comment, must not
flag as a hardcoded secret. Evidence (ecosystem-scan-2026-07-23): awslabs/mcp's
dynamodb-mcp-server DUMMY_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE' (AWS's own
canonical example access-key id), already marked by the maintainer with
`# pragma: allowlist secret`.

Both mechanisms are independent and curated/exact-match only -- a real
secret that merely LOOKS like AKIA-shaped or sits near an unrelated comment
must still flag."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.secret_handling import _is_known_placeholder_secret
from mcp_scanner.models import Confidence


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_aws_example_placeholder_with_suppress_comment_not_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "clean_secret_placeholder"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "hardcoded-secret"]
    assert hits == [], f"placeholder + suppress-comment must not flag, got {hits}"


def test_real_akia_secret_without_suppress_comment_still_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_placeholder"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a real (non-placeholder) AKIA-shaped key without a suppress comment must still flag"


def test_placeholder_literal_without_suppress_comment_also_not_flagged(fixtures_dir):
    # The curated exact-match list works independently of the comment --
    # SDK docs often show the placeholder with no comment at all.
    r = scan_repo(str(fixtures_dir / "clean_secret_placeholder_no_comment"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "hardcoded-secret"]
    assert hits == [], f"known placeholder literal alone must not flag, got {hits}"


def test_unrelated_comment_does_not_suppress_a_real_secret(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_placeholder_unrelated_comment"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "an unrelated comment on the line must not suppress a real secret"


def test_pragma_on_a_real_secret_never_fully_suppresses(fixtures_dir):
    # Round-2 N-vote P0-3(a): in an adversarial/third-party scanning
    # context, `# pragma: allowlist secret` is ATTACKER-controlled -- a
    # malicious external repo could otherwise suppress a whole secret
    # class with one comment per line. A REAL (non-placeholder) secret
    # must NEVER fully vanish on this signal alone -- it may only be
    # demoted (confidence down, tagged "author-suppressed"), still
    # visible in the findings.
    r = scan_repo(
        str(fixtures_dir / "vuln_secret_placeholder_pragma_real_secret"),
        [SecretHandlingDetector()],
    )
    hits = [f for f in r.findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a pragma comment must NEVER fully suppress a real (non-placeholder) secret"
    assert all(f.confidence == Confidence.LOW for f in hits), (
        f"author-suppressed findings must demote confidence, got {[f.confidence for f in hits]}"
    )
    assert any("suppress" in (f.title + f.detail).lower() for f in hits), (
        "author-suppressed findings must be tagged as such so reports surface the signal"
    )


def test_pragma_suppression_is_match_scoped_not_line_scoped(fixtures_dir):
    # Round-2 N-vote P0-3(b): the OLD pragma check skipped the WHOLE LINE
    # once any suppress comment was present -- a real ghp_ token
    # co-located on the same line as a curated placeholder was masked
    # entirely. Each candidate value must be evaluated independently.
    r = scan_repo(
        str(fixtures_dir / "vuln_secret_placeholder_coscoped"),
        [SecretHandlingDetector()],
    )
    hits = [f for f in r.findings if f.vuln_class == "hardcoded-secret"]
    ghp_hits = [f for f in hits if "GitHub" in f.title]
    akia_hits = [f for f in hits if "AWS access key" in f.title]
    assert ghp_hits, f"a real ghp_ token co-located with a placeholder must still flag, got {hits}"
    assert akia_hits == [], f"the curated placeholder on the same line must still fully suppress, got {akia_hits}"


def test_known_placeholder_helper_exact_match_only():
    assert _is_known_placeholder_secret("AKIAIOSFODNN7EXAMPLE")
    assert _is_known_placeholder_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    # Fuzzy/substring must NOT match -- exact-match discipline only.
    assert not _is_known_placeholder_secret("AKIAIOSFODNN7EXAMPLEX")
    assert not _is_known_placeholder_secret("AKIA1234567890ABCDEF")
