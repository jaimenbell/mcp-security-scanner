"""P1d regression: a destructure-aliased child_process binding
(`const { exec: run } = require('child_process')`) must still be recognized
as a shell-injection sink when the alias -- not the original name -- is
called. Previously this was invisible: the sink regex only matched the
literal name 'exec', not any rebound alias."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector


def test_destructure_aliased_exec_still_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_param_alias_js"), [ParamInjectionDetector()])
    hits = [f for f in r.findings if f.vuln_class == "shell-injection"]
    assert hits, (
        "run(...) -- an alias of exec via destructuring -- must still be "
        f"flagged, got {r.findings}"
    )
