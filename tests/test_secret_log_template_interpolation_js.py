"""P2 regression (adversarial verify-pass on d1c1bb8, 2026-07-22): a
secret-named identifier interpolated inside a JS/TS template literal
(`` logger.log(`token: ${apiKey}`) ``) must be flagged -- previously
_JS_STRING_LITERAL stripped the whole backtick span, ${...} included,
before the secret-name scan ever ran, producing 0 findings for an
extremely common real-world Node.js logging pattern."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretHandlingDetector


def test_secret_named_template_interpolation_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_log_template_js"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-in-log"]
    assert hits, (
        "apiKey interpolated inside a template literal must be flagged, "
        f"got {r.findings}"
    )


def test_glued_interpolation_and_non_template_dollar_brace_quiet(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "clean_secret_log_template_js"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-in-log"]
    assert hits == [], (
        "apiKeyValidator.isValid (glued compound word inside ${...}) and a "
        "literal '${price}' inside a plain double-quoted (non-template) "
        f"string must not flag, got {hits}"
    )
