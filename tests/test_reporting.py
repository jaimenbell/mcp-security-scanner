from mcp_scanner.models import ScanResult, Finding, Severity, Confidence
from mcp_scanner.reporting import render_markdown, render_json
import json


def _finding(sev):
    return Finding(
        vuln_class="demo", title="demo finding", severity=sev,
        confidence=Confidence.HIGH, file="a.py", line=3,
        detail="d", remediation="r",
    )


def test_clean_bill_true_with_only_p2_p3():
    r = ScanResult(target="x")
    r.add(_finding(Severity.P2))
    r.add(_finding(Severity.P3))
    assert r.clean_bill is True


def test_clean_bill_false_with_p1():
    r = ScanResult(target="x")
    r.add(_finding(Severity.P1))
    assert r.clean_bill is False


def test_sorted_by_severity():
    r = ScanResult(target="x")
    r.add(_finding(Severity.P3))
    r.add(_finding(Severity.P0))
    r.add(_finding(Severity.P2))
    order = [f.severity for f in r.sorted_findings]
    assert order == [Severity.P0, Severity.P2, Severity.P3]


def test_markdown_has_boundary_and_confidence():
    r = ScanResult(target="repo", files_scanned=5)
    r.add(_finding(Severity.P1))
    md = render_markdown(r)
    assert "static" in md.lower()
    assert "confidence: high" in md
    assert "Capability boundary" in md


def test_json_roundtrips():
    r = ScanResult(target="repo", files_scanned=5)
    r.add(_finding(Severity.P1))
    data = json.loads(render_json(r))
    assert data["clean_bill"] is False
    assert data["findings"][0]["vuln_class"] == "demo"
    assert data["findings"][0]["confidence"] == "high"
