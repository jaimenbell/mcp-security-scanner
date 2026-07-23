"""Wave-1 FP class 1b: a self-signed TEST certificate (a throwaway keypair
generated to stand up a local HTTPS test server) tracked at a test-fixture
path must not flag as a leaked secret. Evidence (ecosystem-scan-2026-07-23):
microsoft/playwright-mcp's tests/testserver/cert.pem + key.pem, both
self-signed (CN=playwright-test, issuer==subject).

Demotion requires BOTH a test-fixture path AND a provable self-signed
marker (issuer == subject, parsed via the optional `cryptography` package)
-- never on ".pem extension" alone. A cert whose issuer != subject (a
CA-issued-looking cert, even placed at a test path) must still flag, and a
self-signed cert OUTSIDE a test path must still flag -- both prove the
demotion can't mask a real leaked production credential.
"""
from pathlib import Path

import pytest

from mcp_scanner.detectors import SecretHandlingDetector
from mcp_scanner.detectors.base import RepoContext
from mcp_scanner.detectors.secret_handling import (
    _is_test_fixture_path,
    _is_self_signed_test_cert,
)

PEM_DIR = Path(__file__).parent / "fixtures" / "pem_material"


def test_selfsigned_cert_at_test_path_demoted():
    # tracked path is relative to ctx.root -- point root at "tests/" so the
    # tracked-relative path carries a "fixtures" test-path segment and
    # content inspection can resolve to the real file on disk.
    ctx = RepoContext(
        root=PEM_DIR.parent.parent,  # .../tests
        files=[], tracked={"fixtures/pem_material/selfsigned_cert.pem"}, is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf == [], f"self-signed test cert at a test path must be demoted, got {tf}"


def test_selfsigned_cert_outside_test_path_still_flagged():
    # Root IS the pem_material dir directly -- the tracked-relative path
    # then carries NO "test"/"fixtures" path segment at all.
    ctx = RepoContext(root=PEM_DIR, files=[], tracked={"selfsigned_cert.pem"}, is_git=True)
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf, "a self-signed cert with NO test-path marker must still flag"


def test_ca_issued_cert_at_test_path_still_flagged():
    # issuer != subject -- not provably self-signed -- must stay flagged
    # even though the path looks like a test fixture.
    ctx = RepoContext(
        root=PEM_DIR.parent.parent,
        files=[], tracked={"fixtures/pem_material/caissued_cert.pem"}, is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf, "a non-self-signed (CA-issuer-shaped) cert must still flag even at a test path"


def test_selfsigned_key_paired_with_selfsigned_cert_demoted():
    ctx = RepoContext(
        root=PEM_DIR.parent.parent,
        files=[],
        tracked={
            "fixtures/pem_material/paired_selfsigned/cert.pem",
            "fixtures/pem_material/paired_selfsigned/key.pem",
        },
        is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf == [], f"a private key paired with a self-signed test cert must be demoted, got {tf}"


def test_key_without_sibling_cert_still_flagged():
    # Isolated directory with only the key present -- no sibling cert.
    ctx = RepoContext(
        root=PEM_DIR.parent.parent,
        files=[], tracked={"fixtures/pem_material/lonely_key/key.pem"}, is_git=True,
    )
    findings = SecretHandlingDetector().run(ctx)
    tf = [f for f in findings if f.vuln_class == "tracked-secret-file"]
    assert tf, "a lone .pem/.key file with no self-signed sibling cert must still flag"


# --- unit-level guards on the helper functions themselves -------------------

def test_is_test_fixture_path():
    for p in ("tests/testserver/cert.pem", "test/fixtures/x.pem",
              "src/__tests__/y.key", "pkg/fixtures/z.pem"):
        assert _is_test_fixture_path(p), f"{p} should be recognized as a test path"
    assert not _is_test_fixture_path("config/prod-cert.pem")
    assert not _is_test_fixture_path("src/server/cert.pem")


def test_unparseable_file_never_demotes():
    # A corrupt/non-PEM file at a test path must never be treated as
    # provably self-signed -- unknown stays flagged (over-flag direction).
    assert _is_self_signed_test_cert(PEM_DIR / "does_not_exist.pem") is False


def test_selfsigned_helper_directly():
    assert _is_self_signed_test_cert(PEM_DIR / "selfsigned_cert.pem") is True
    assert _is_self_signed_test_cert(PEM_DIR / "caissued_cert.pem") is False


def test_missing_cryptography_package_never_demotes(monkeypatch):
    # Hard-rail proof: if the optional `cryptography` package is not
    # installed, self-signed detection must fail CLOSED (return False,
    # i.e. the caller keeps the P1 flag) rather than guessing.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("simulated: cryptography not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert _is_self_signed_test_cert(PEM_DIR / "selfsigned_cert.pem") is False
