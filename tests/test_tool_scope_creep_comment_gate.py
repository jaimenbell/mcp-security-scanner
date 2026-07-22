"""P0 regression: a comment mentioning gate vocabulary (e.g. '# TODO: needs
auth_required check' / '// TODO: needs auth_required check') must never be
treated as gate evidence -- only real gate code (decorator/env-check) counts.
Covers both the Python AST path and the JS/TS line-window regex path."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Severity


def test_python_comment_mentioning_gate_vocabulary_not_treated_as_gate(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_tool_scope_comment_py"), [ToolScopeCreepDetector()])
    hits = [f for f in r.findings if f.vuln_class == "tool-scope-creep"]
    assert hits, (
        "a '# TODO: needs auth_required check' comment must not suppress "
        "the finding for an ungated os.remove sink"
    )
    assert any(f.severity == Severity.P1 for f in hits)


def test_js_comment_mentioning_gate_vocabulary_not_treated_as_gate(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_tool_scope_comment_js"), [ToolScopeCreepDetector()])
    hits = [f for f in r.findings if f.vuln_class == "tool-scope-creep"]
    assert hits, (
        "a '// TODO: needs auth_required check' comment must not suppress "
        "the finding for an ungated fs.unlinkSync sink"
    )
    assert any(f.severity == Severity.P1 for f in hits)
