"""P1b regression: secret_leak_response._js_return_object_keys's brace-depth
tracker must not be fooled by a '}' inside a string VALUE -- that must not
prematurely close the return-object window before a later secret-named key
(apiKey) is reached."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretLeakResponseDetector


def test_brace_inside_string_value_does_not_hide_later_secret_key(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_leak_brace_js"), [SecretLeakResponseDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-leak-via-tool-response"]
    assert hits, (
        "apiKey must still be flagged even though an earlier string value "
        f"on the same object literal contains a stray '}}', got {r.findings}"
    )
    # Both the secret-named-key signal and the hardcoded-secret-value signal
    # should fire independently (matches the two-signals-per-field contract
    # already documented for _js_return_object_keys).
    assert len(hits) >= 2
