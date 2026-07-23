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


def test_known_placeholder_helper_exact_match_only():
    assert _is_known_placeholder_secret("AKIAIOSFODNN7EXAMPLE")
    assert _is_known_placeholder_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    # Fuzzy/substring must NOT match -- exact-match discipline only.
    assert not _is_known_placeholder_secret("AKIAIOSFODNN7EXAMPLEX")
    assert not _is_known_placeholder_secret("AKIA1234567890ABCDEF")
