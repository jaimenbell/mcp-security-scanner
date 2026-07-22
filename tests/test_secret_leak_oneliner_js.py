"""P2-honesty regression: secret_leak_response.py's old docstring claimed a
compressed one-line object-literal return (`return {a: 1};`) was already
caught by the whole-object/process.env checks. It wasn't -- `return
{apiKey: process.env.API_KEY, other: 1};` produced 0 findings. Fixed by
decomposing the same-line-closed object literal too, not just the
one-field-per-line multi-line style."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import SecretLeakResponseDetector


def test_compressed_one_line_object_return_flags_secret_key(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_secret_leak_oneliner_js"), [SecretLeakResponseDetector()])
    hits = [f for f in r.findings if f.vuln_class == "secret-leak-via-tool-response"]
    assert hits, (
        "a same-line `return {apiKey: process.env.API_KEY, other: 1};` must "
        f"still be decomposed and flagged, got {r.findings}"
    )
    assert any("apiKey" in f.detail or "apiKey" in f.title for f in hits)
