"""Round-3 N-vote fix pass. Meta-instruction (both refuters, A2's closing
line): root-cause fixes, not more special-casing. Round-2's failures were
all end-of-pass special cases (fake-marker full-suppress, a cert-demotion
OR-gate, a keyword-blind regex heuristic). ONE LAW now governs every
demotion in this codebase: full suppression is reserved for OUR OWN
curated exact-match judgment (``_is_known_placeholder_secret``); every
other signal -- pragma comments, fake-value markers, test-shaped cert
identity -- may only demote confidence and tag the finding. It never
disappears.
"""
import ast
from pathlib import Path

import pytest

from mcp_scanner.detectors.base import RepoContext, SourceFile
from mcp_scanner.detectors import SecretHandlingDetector, ParamInjectionDetector
from mcp_scanner.detectors.secret_handling import _has_fake_marker
from mcp_scanner.models import Confidence
from mcp_scanner.scanner import scan_repo

pytest.importorskip("cryptography")


def _scan_src(src: str):
    tree = ast.parse(src)
    f = SourceFile(path=Path("x.py"), rel="x.py", text=src, tree=tree, lines=src.splitlines())
    ctx = RepoContext(root=Path("."), files=[f], tracked=set(), is_git=False)
    return SecretHandlingDetector().run(ctx)


# ---------------------------------------------------------------------------
# P0-A: fake-marker must demote, never suppress (A2 repro, verbatim shape)
# ---------------------------------------------------------------------------

def test_a2_repro_prod_api_key_containing_sample_tier_still_flags():
    # A2's exact repro shape: a REAL secret whose value merely CONTAINS
    # "sample" as an unrelated tenant/tier component -- round-2's
    # full-suppress made this vanish to zero findings.
    src = (
        'PROD_API_KEY = '
        '"sample-tier-9f8a7b6c1234567890abcdef1234567890abcdef1234567890abcdef1234efab"\n'
    )
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a real secret merely containing a marker word must still produce a finding"
    assert hits[0].confidence == Confidence.LOW
    assert "fake-marker" in hits[0].title


def test_a2_repro_demo_tenant_bearer_still_flags():
    src = 'AUTH = "Bearer demo-tenant-xK9pQm2vN8rL5wYs3Tz7Ab1Cd4Ef6Gh0Ij9Kl2Mn5Op8Qr1"\n'
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a Bearer token merely containing 'demo-tenant' must still produce a finding"
    assert hits[0].confidence == Confidence.LOW
    assert "fake-marker" in hits[0].title


def test_fake_marker_is_word_boundary_not_substring():
    # "password123" contains no whole-word marker -- must NOT demote.
    # "testament" contains "test" only as a substring inside a real word
    # (no separator) -- must NOT demote either (tokenized, not naive \\b).
    assert not _has_fake_marker("xK9pQm2vN8rL5wYs3passwordZZZ123")
    assert not _has_fake_marker("testamentVaultKey9f8a7b6c1234567890")


def test_fake_marker_matches_underscore_and_hyphen_joined_words():
    # The exact class of value that broke the naive \\b regex in round 2
    # (underscore is a \\w char, so \\bfake\\b never matched inside a
    # snake_case identifier at all).
    assert _has_fake_marker("github_pat_fake_test_token_1234")
    assert _has_fake_marker("sample-tier-abc123")
    assert _has_fake_marker("xxxxxxxx12345678")


def test_real_secret_with_no_marker_stays_high_confidence():
    src = 'PROD_API_KEY = "9f8a7b6c1234567890abcdef1234567890abcdef1234567890abcdef1234efab"\n'
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits
    assert hits[0].confidence == Confidence.MEDIUM  # AST-branch baseline confidence
    assert "fake-marker" not in hits[0].title


# ---------------------------------------------------------------------------
# P0-B: cert demotion requires the test-identity marker; validity/key-size
# are corroborating only, never independently sufficient. Demotion is a
# LOW-confidence tagged finding, never zero-trace.
# ---------------------------------------------------------------------------

PEM_DIR = Path(__file__).parent / "fixtures" / "pem_material"


def test_p0b_repro_prod_cn_short_validity_still_flags():
    # A2's exact repro: a self-signed cert with a PROD-shaped CN (no
    # test/localhost/example/demo/dummy/mock marker) but a SHORT (<=90
    # day) validity and a normal 2048-bit key, sitting at a test-fixture
    # path. Round-2's OR-gate let validity-alone demote this to total
    # invisibility. Must stay a flagged (even if demoted-confidence)
    # finding -- never zero-trace.
    from mcp_scanner.detectors.secret_handling import _cert_has_test_shaped_identity
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "payments-api.mycompany-prod.internal")])
    now = datetime.datetime(2026, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))  # exactly the repro boundary
        .sign(key, hashes.SHA256())
    )
    tmp_dir = PEM_DIR / "p0b_prod_short_validity"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cert_path = tmp_dir / "cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Direct helper: must NOT be treated as test-shaped (no CN/SAN marker).
    assert _cert_has_test_shaped_identity(cert_path) is False, (
        "validity alone must no longer be sufficient -- the CN/SAN marker is required"
    )

    ctx = RepoContext(
        root=PEM_DIR.parent.parent,
        files=[], tracked={"fixtures/pem_material/p0b_prod_short_validity/cert.pem"}, is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf, "a prod-CN self-signed cert must stay flagged even with a short validity window"


def test_demoted_test_cert_is_low_confidence_tagged_not_zero_trace():
    # A GENUINELY test-shaped cert (CN marker present) must still emit a
    # finding -- LOW confidence, tagged -- never silently vanish.
    ctx = RepoContext(
        root=PEM_DIR.parent.parent,
        files=[], tracked={"fixtures/pem_material/selfsigned_cert.pem"}, is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf, "a demoted test cert must still emit a finding, never zero-trace"
    assert tf[0].confidence == Confidence.LOW
    assert "test-cert" in tf[0].title


def test_ca_issued_cert_at_test_path_stays_high_confidence():
    ctx = RepoContext(
        root=PEM_DIR.parent.parent,
        files=[], tracked={"fixtures/pem_material/caissued_cert.pem"}, is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf
    assert tf[0].confidence == Confidence.HIGH
    assert "test-cert" not in tf[0].title


# ---------------------------------------------------------------------------
# P0-C: keyword-preceded regex literals + fail-closed brace walker
# ---------------------------------------------------------------------------

def test_p0c_shadow6_keyword_preceded_regex_no_longer_leaks_braces():
    # `return /^{$/.test(x)` -- "return" is alnum, so the OLD regex-context
    # heuristic (symbols only) never recognized this as a regex literal;
    # its brace leaked into the scope walk, merging spans, and masked a
    # REAL cp.exec(cmd) shell-injection sink elsewhere in the same file.
    r = scan_repo("tests/fixtures/vuln_param_regexp_keyword_fp", [ParamInjectionDetector()])
    hits = [f for f in r.findings if f.vuln_class == "shell-injection"]
    lines = {f.line for f in hits}
    assert 19 in lines, f"the real cp.exec(cmd) sink must not be masked by a keyword-regex brace leak, got {hits}"


def test_p0c_unbalanced_braces_fail_closed_to_over_flag():
    # A file whose braces genuinely don't balance must discard ALL scope
    # info -- every .exec receiver becomes unresolvable, matching base
    # (pre-scope-fix) over-flag parity, never silently under-flagging.
    # This includes shadowRegex()'s cp.exec("x") at line 16, which WOULD
    # otherwise legitimately demote in a well-formed file -- proving the
    # discard is total, not partial.
    r = scan_repo("tests/fixtures/vuln_param_regexp_unbalanced_braces", [ParamInjectionDetector()])
    hits = [f for f in r.findings if f.vuln_class == "shell-injection"]
    lines = {f.line for f in hits}
    assert 20 in lines, f"the real sink must stay flagged, got {hits}"
    assert 16 in lines, (
        f"scope discard must be TOTAL -- even the shadowed-regex exec call must over-flag "
        f"when the file's braces don't balance, got {hits}"
    )


# ---------------------------------------------------------------------------
# P1 (B2): the revived AST branch must route through the shared
# _name_looks_secret helper (pagination exclusion + glued-word guard),
# not raw _SECRET_NAME.search.
# ---------------------------------------------------------------------------

def test_b2_pagination_named_assignment_excluded_via_ast_branch():
    src = "expected_response.next_token = 'next-token-value-abc123def456'\n"
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits == [], f"a pagination-shaped assignment must be excluded via the AST branch too, got {hits}"


def test_b2_real_credential_assignment_still_flags_via_ast_branch():
    src = "self.access_token = 'a-real-looking-credential-value-9f8a7b6c'\n"
    findings = _scan_src(src)
    hits = [f for f in findings if f.vuln_class == "hardcoded-secret"]
    assert hits, "a real credential-shaped assignment must still flag via the AST branch"
