import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.models import Confidence, Grade, Severity


@pytest.fixture
def vuln(fixtures_dir):
    return scan_repo(str(fixtures_dir / "vuln_param_js"), [ParamInjectionDetector()])


@pytest.fixture
def clean(fixtures_dir):
    return scan_repo(str(fixtures_dir / "clean_param_js"), [ParamInjectionDetector()])


def _classes(r):
    return {f.vuln_class for f in r.findings}


def test_exec_and_shell_spawn_flagged(vuln):
    assert "shell-injection" in _classes(vuln)
    hits = [f for f in vuln.findings if f.vuln_class == "shell-injection"]
    assert len(hits) >= 2


def test_eval_and_new_function_are_flagged_but_ungraded_and_capped(vuln):
    """CONTRACT CHANGED 2026-07-29 (grading-honesty pass).

    The param-injection detector still calls JS eval()/new Function() a P0 --
    that judgment about the pattern is unchanged, and is asserted directly
    against the detector below. What changed is what a SCAN emits: .js has no
    AST, so neither the reachability nor the dataflow pass can analyse the
    file, and for a dataflow class the P0 rung ('exploitable now, no
    preconditions') is precisely the dataflow claim that was never checked.
    A scan therefore reports it at P2/LOW, labelled UNGRADED with a stated
    reason, rather than at a severity the evidence does not support.

    Why this matters: on 2026-07-29 the four ONLY P0s in a 58-finding
    measurement across five third-party MCP servers were JS `.eval()` hits,
    all four false. Both halves are asserted here so neither can rot.
    """
    ev = [f for f in vuln.findings if f.vuln_class == "code-eval"]
    assert len(ev) >= 2
    assert all(f.grade is Grade.UNGRADED for f in ev)
    assert all(f.grade_reason for f in ev)
    assert all(f.severity == Severity.P2 for f in ev)
    assert all(f.confidence is Confidence.LOW for f in ev)


def test_detector_itself_still_rates_js_eval_p0(fixtures_dir):
    """The detector's own verdict is untouched -- the cap is applied by the
    post-pass, not by weakening the detector. Asserted against a DIFFERENT
    value (P0) from the scan-level assertion above (P2), so the two cannot
    both be satisfied by one constant."""
    from mcp_scanner.detectors import ParamInjectionDetector
    from mcp_scanner.scanner import build_context

    ctx, _ = build_context(str(fixtures_dir / "vuln_param_js"))
    raw = [f for f in ParamInjectionDetector().run(ctx)
           if f.vuln_class == "code-eval"]
    assert raw and all(f.severity == Severity.P0 for f in raw)


def test_ssrf_and_traversal_flagged(vuln):
    assert "ssrf" in _classes(vuln)
    assert "path-traversal" in _classes(vuln)


def test_findings_land_on_js_file(vuln):
    assert all(f.file.endswith("server.js") for f in vuln.findings)


def test_clean_param_js_quiet(clean):
    bad = [f for f in clean.findings
           if f.vuln_class in ("shell-injection", "code-eval",
                               "unsafe-deserialization", "ssrf", "path-traversal")]
    assert bad == [], f"clean param_js fixture should be quiet, got {bad}"
