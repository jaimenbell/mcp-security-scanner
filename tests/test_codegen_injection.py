from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import CodegenInjectionDetector
from mcp_scanner.models import Severity


def test_vuln_codegen_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "vuln_codegen"), [CodegenInjectionDetector()])
    cg = [f for f in r.findings if f.vuln_class == "codegen-injection"]
    assert cg, "autoescape-off codegen should be flagged"
    # autoescape off + code template present -> P1
    assert any(f.severity == Severity.P1 for f in cg)
    # hand-rolled replace('"','\\"') in the template should also be caught
    assert any("Hand-rolled" in f.title for f in cg)


def test_clean_codegen_no_finding(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "clean_codegen"), [CodegenInjectionDetector()])
    cg = [f for f in r.findings if f.vuln_class == "codegen-injection"]
    assert cg == [], f"autoescape-on HTML template must not be flagged, got {cg}"
