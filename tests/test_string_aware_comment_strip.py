"""P1a regression at the detector level (js_util.test_js_util covers the
util function directly): a '// '-bearing string literal must not swallow a
sink call or a secret-named log argument that follows it on the same line."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector, SecretHandlingDetector


def test_exec_after_string_containing_slash_slash_still_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_param_string_slash_js"), [ParamInjectionDetector()])
    hits = [f for f in r.findings if f.vuln_class == "shell-injection"]
    assert hits, (
        "exec(cmd) after a '// '-bearing string literal must still be "
        f"flagged, got {r.findings}"
    )


def test_secret_arg_after_string_containing_slash_slash_still_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_log_string_slash_js"), [SecretHandlingDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-in-log"]
    assert hits, (
        "the 'password' argument after a '// '-bearing string literal must "
        f"still be flagged, got {r.findings}"
    )
