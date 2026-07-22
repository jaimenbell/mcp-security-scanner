"""P1c regression: `import { exec } from 'node:child_process'` (the
documented Node 16+ convention) must be recognized by the same shell-
injection check as the bare 'child_process' specifier -- previously it was a
total blind spot (0 findings)."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector


def test_node_prefixed_child_process_import_still_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_param_node_prefix_js"), [ParamInjectionDetector()])
    hits = [f for f in r.findings if f.vuln_class == "shell-injection"]
    assert hits, (
        "exec() imported via 'node:child_process' must still be flagged, "
        f"got {r.findings}"
    )
