"""CLI wiring for the `report` subcommand (spec 2026-07-23).

`mcp-scan report <scan.json> [--annotations triage.toml] [--client ...
--engagement ... --scope ...] [--out report.html] [--md report.md]`.
The report NEVER re-runs scans -- it only reads the JSON.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp_scanner.cli import main
from mcp_scanner.finding_identity import compute_finding_id
from mcp_scanner.models import ScanResult, Finding, Severity, Confidence


def _scan_json(tmp_path: Path) -> Path:
    r = ScanResult(target="C:/scans/acme", files_scanned=3, scan_date="2026-07-23")
    r.add(Finding(
        vuln_class="param-injection", title="shell=True call",
        severity=Severity.P1, confidence=Confidence.HIGH,
        file="a.py", line=5, detail="d", remediation="r",
    ))
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(r.to_dict(), indent=2), encoding="utf-8")
    return p


def test_report_command_prints_markdown_by_default(tmp_path, capsys):
    rc = main(["report", str(_scan_json(tmp_path)), "--client", "Acme Corp"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "## 2. Executive summary" in out
    assert "Acme Corp" in out


def test_report_command_writes_html_and_md_files(tmp_path, capsys):
    scan = _scan_json(tmp_path)
    out_html = tmp_path / "report.html"
    out_md = tmp_path / "report.md"
    rc = main(["report", str(scan), "--client", "Acme",
               "--engagement", "Week-1 Audit", "--scope", "1 server",
               "--out", str(out_html), "--md", str(out_md)])
    assert rc == 0
    html_text = out_html.read_text(encoding="utf-8")
    md_text = out_md.read_text(encoding="utf-8")
    assert "<style>" in html_text and "Week-1 Audit" in html_text
    assert "## 3. Triage summary" in md_text


def test_report_command_applies_annotations(tmp_path, capsys):
    scan = _scan_json(tmp_path)
    fid = compute_finding_id("param-injection", "a.py", "shell=True call")
    triage = tmp_path / "triage.toml"
    triage.write_text(
        f'[findings.{fid}]\nverdict = "confirmed"\nnote = "verified by hand"\n',
        encoding="utf-8")
    rc = main(["report", str(scan), "--annotations", str(triage)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "verified by hand" in out


def test_report_command_bad_input_is_a_clean_error(tmp_path, capsys):
    bad = tmp_path / "nope.json"
    rc = main(["report", str(bad)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "nope.json" in err


def test_plain_scan_cli_still_works_unchanged(capsys):
    """The flat `mcp-scan <path>` surface must be untouched by the
    subcommand dispatch."""
    rc = main(["tests/fixtures/clean_auth"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "# MCP Server Security Scan" in out
