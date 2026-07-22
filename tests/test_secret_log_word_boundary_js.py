"""Cheap-win regression: secret_handling's JS log check now reuses
secret_leak_response's word-boundary guard (_name_looks_secret, moved to
secret_handling.py so both detectors share one implementation), so a name
that merely CONTAINS a secret-vocabulary substring glued inside a longer,
unrelated identifier (apiKeyValidator, tokenizerConfig) no longer
false-flags -- while a real secret-named argument still does."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretHandlingDetector


def test_real_secret_arg_still_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_log_boundary_js"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-in-log"]
    assert hits, f"a real 'password' argument must still be flagged, got {r.findings}"


def test_glued_substring_names_not_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "clean_secret_log_boundary_js"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-in-log"]
    assert hits == [], (
        "apiKeyValidator/tokenizerConfig only CONTAIN a secret-vocabulary "
        f"substring glued inside a longer word; must not flag, got {hits}"
    )
