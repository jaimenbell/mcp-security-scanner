"""The `mcp-scan report` generator (spec: client-report-generator 2026-07-23).

Covers: scan-JSON loading (report NEVER re-runs scans), triage.toml
annotations, verdict attachment, unknown-id loud-warning behavior, the
fixed section order, self-containment of the HTML (zero external URLs),
and the no-hardcoded-counts template gate.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from mcp_scanner import report_generator as rg
from mcp_scanner.finding_identity import compute_finding_id


# --------------------------------------------------------------------- #
# Shared synthetic scan fixtures (dicts, the JSON contract)
# --------------------------------------------------------------------- #
def _scan_dict(with_ids: bool = True) -> dict:
    findings = [
        {
            "vuln_class": "param-injection",
            "title": "subprocess with shell=True",
            "severity": "P1", "confidence": "high",
            "file": "srv/tools.py", "line": 42,
            "detail": "subprocess.run(cmd, shell=True) on a tool parameter",
            "remediation": "Use an argv list; never shell=True.",
            "snippet": "subprocess.run(cmd, shell=True)",
            "reachability": "reachable", "reachability_evidence": "",
            "taint": "tainted",
        },
        {
            "vuln_class": "secret-handling",
            "title": "hardcoded secret assignment",
            "severity": "P2", "confidence": "low",
            "file": "srv/config.py", "line": 7,
            "detail": "API_KEY assigned a secret-shaped literal",
            "remediation": "Move to an env var.",
            "snippet": "API_KEY = \"sk-...\"",
            "reachability": "unknown", "reachability_evidence": "",
            "taint": "unknown",
        },
    ]
    if with_ids:
        for f in findings:
            f["finding_id"] = compute_finding_id(
                f["vuln_class"], f["file"], f["title"])
    return {
        "target": "C:/scans/acme-mcp",
        "files_scanned": 12,
        "counts_by_severity": {"P0": 0, "P1": 1, "P2": 1, "P3": 0},
        "clean_bill": False,
        "findings": findings,
        "errors": [],
        "scan_meta": {
            "scanner_version": "abc1234",
            "suite_counts": {"total": 346, "passed": 337, "skipped": 9},
            "scan_date": "2026-07-23",
        },
    }


def _write_scan(tmp_path: Path, data: dict, name="scan.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


def _fid(i: int = 0) -> str:
    return _scan_dict()["findings"][i]["finding_id"]


def _write_annotations(tmp_path: Path, body: str, name="triage.toml") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# --------------------------------------------------------------------- #
# load_scan
# --------------------------------------------------------------------- #
def test_load_scan_keeps_embedded_finding_ids(tmp_path):
    p = _write_scan(tmp_path, _scan_dict(with_ids=True))
    scan = rg.load_scan(p)
    assert [f["finding_id"] for f in scan["findings"]] == [_fid(0), _fid(1)]


def test_load_scan_computes_ids_for_older_json_without_them(tmp_path):
    """Backward compat: pre-finding_id scan JSONs (e.g. the ecosystem raw
    results) get deterministic ids computed by the same shared function."""
    p = _write_scan(tmp_path, _scan_dict(with_ids=False))
    scan = rg.load_scan(p)
    assert [f["finding_id"] for f in scan["findings"]] == [_fid(0), _fid(1)]


def test_load_scan_multi_result_mapping_needs_target_key(tmp_path):
    multi = {"org/repo-a": _scan_dict(), "org/repo-b": _scan_dict()}
    p = _write_scan(tmp_path, multi)
    with pytest.raises(rg.ReportInputError) as ei:
        rg.load_scan(p)
    assert "org/repo-a" in str(ei.value)  # error lists the available keys
    scan = rg.load_scan(p, target="org/repo-b")
    assert scan["findings"]


def test_load_scan_list_of_results_needs_target_key(tmp_path):
    p = _write_scan(tmp_path, [_scan_dict(), _scan_dict()])
    with pytest.raises(rg.ReportInputError):
        rg.load_scan(p)
    scan = rg.load_scan(p, target="0")
    assert scan["findings"]


# --------------------------------------------------------------------- #
# load_annotations
# --------------------------------------------------------------------- #
def test_load_annotations_parses_verdicts(tmp_path):
    p = _write_annotations(tmp_path, f"""
[findings.{_fid(0)}]
verdict = "confirmed"
note = "Reproduced by hand; the parameter reaches the shell."
reviewed_by = "Jaimen"

[findings.{_fid(1)}]
verdict = "false-positive"
note = "Test-only fixture value."
""")
    ann = rg.load_annotations(p)
    assert ann[_fid(0)]["verdict"] == "confirmed"
    assert ann[_fid(0)]["reviewed_by"] == "Jaimen"
    assert ann[_fid(1)]["verdict"] == "false-positive"


def test_load_annotations_rejects_unknown_verdict(tmp_path):
    p = _write_annotations(tmp_path, """
[findings.abc123abc123]
verdict = "totally-fine"
""")
    with pytest.raises(rg.ReportInputError):
        rg.load_annotations(p)


# --------------------------------------------------------------------- #
# model: verdicts, unknown ids, counts
# --------------------------------------------------------------------- #
def _model(tmp_path, ann_body: "str | None" = None):
    scan = rg.load_scan(_write_scan(tmp_path, _scan_dict()))
    ann = {}
    ann_name = ""
    if ann_body is not None:
        ann_path = _write_annotations(tmp_path, ann_body)
        ann = rg.load_annotations(ann_path)
        ann_name = "triage.toml"
    return rg.build_report_model(
        scan, ann, client="Acme Corp", engagement="Week-1 Audit",
        scope="1 MCP server", annotations_name=ann_name)


def test_model_attaches_verdicts_and_defaults_unreviewed(tmp_path):
    m = _model(tmp_path, f"""
[findings.{_fid(0)}]
verdict = "confirmed"
note = "real"
""")
    by_id = {f["finding_id"]: f for f in m["findings"]}
    assert by_id[_fid(0)]["verdict"] == "confirmed"
    assert by_id[_fid(1)]["verdict"] == "unreviewed"


def test_model_unknown_annotation_ids_go_to_warnings_never_dropped(tmp_path):
    m = _model(tmp_path, f"""
[findings.{_fid(0)}]
verdict = "confirmed"
note = "real"

[findings.deadbeef0000]
verdict = "false-positive"
note = "this finding no longer exists in the scan"
""")
    assert [w["finding_id"] for w in m["unknown_annotations"]] == ["deadbeef0000"]
    # ... and the known one still applied.
    assert any(f["verdict"] == "confirmed" for f in m["findings"])


def test_model_counts_are_data_derived(tmp_path):
    m = _model(tmp_path, f"""
[findings.{_fid(0)}]
verdict = "confirmed"
note = "real"

[findings.{_fid(1)}]
verdict = "false-positive"
note = "fixture"
""")
    assert m["counts"]["raw_total"] == 2
    assert m["counts"]["by_verdict"]["confirmed"] == 1
    assert m["counts"]["by_verdict"]["false-positive"] == 1
    assert m["counts"]["by_verdict"]["unreviewed"] == 0
    assert m["counts"]["severity_verdict"]["P1"]["confirmed"] == 1


def test_model_remediation_guidance_curated_plus_generic_fallback(tmp_path):
    m = _model(tmp_path)
    by_id = {f["finding_id"]: f for f in m["findings"]}
    g = by_id[_fid(0)]["remediation_guidance"]
    assert g == rg.REMEDIATION_GUIDANCE["param-injection"]
    # Unmapped class falls back to the honest generic text.
    scan = _scan_dict()
    scan["findings"][0]["vuln_class"] = "brand-new-class"
    m2 = rg.build_report_model(scan, {}, client="c", engagement="e", scope="s")
    assert m2["findings"][0]["remediation_guidance"] == rg.GENERIC_REMEDIATION


# --------------------------------------------------------------------- #
# markdown render: fixed section order, meta from scan JSON
# --------------------------------------------------------------------- #
def test_markdown_sections_in_spec_order(tmp_path):
    md = rg.render_markdown_report(_model(tmp_path))
    positions = [md.index(h) for h in (
        "## 1. Engagement",           # cover/meta
        "## 2. Executive summary",
        "## 3. Triage summary",
        "## 4. Findings detail",
        "## 5. Methodology",
        "## 6. Appendix",
    )]
    assert positions == sorted(positions)


def test_markdown_cover_reads_meta_from_scan_json(tmp_path):
    md = rg.render_markdown_report(_model(tmp_path))
    assert "Acme Corp" in md
    assert "Week-1 Audit" in md
    assert "abc1234" in md          # scanner_version from scan_meta
    assert "2026-07-23" in md       # scan date from scan_meta
    assert "346" in md              # suite total from scan_meta


def test_markdown_unknown_ids_render_loud_warning_section(tmp_path):
    m = _model(tmp_path, """
[findings.deadbeef0000]
verdict = "false-positive"
note = "stale"
""")
    md = rg.render_markdown_report(m)
    assert "deadbeef0000" in md
    assert "stale triage" in md.lower()


def test_markdown_empty_scan_renders_clean_statement(tmp_path):
    scan = _scan_dict()
    scan["findings"] = []
    scan["counts_by_severity"] = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    scan["clean_bill"] = True
    m = rg.build_report_model(scan, {}, client="Acme", engagement="E", scope="S")
    md = rg.render_markdown_report(m)
    assert "clean bill" in md.lower()


# --------------------------------------------------------------------- #
# HTML render: self-contained, escaped
# --------------------------------------------------------------------- #
def _external_url_attrs(html_text: str) -> list[str]:
    return re.findall(
        r"""(?:src|href)\s*=\s*["'](?:https?:)?//[^"']*["']""",
        html_text, flags=re.IGNORECASE)


def test_html_has_zero_external_src_href(tmp_path):
    """Acceptance gate 4: emailable single file, no external assets."""
    html_text = rg.render_html_report(_model(tmp_path, f"""
[findings.{_fid(0)}]
verdict = "confirmed"
note = "real"
"""))
    assert _external_url_attrs(html_text) == []
    assert "<style>" in html_text          # CSS is inline
    assert "<link" not in html_text.lower()
    assert "@import" not in html_text
    assert "<script" not in html_text.lower()


def test_html_escapes_untrusted_scan_content(tmp_path):
    scan = _scan_dict()
    scan["findings"][0]["title"] = "<script>alert(1)</script>"
    scan["findings"][0]["detail"] = "<img src=//evil.example/x>"
    m = rg.build_report_model(scan, {}, client="Acme", engagement="E", scope="S")
    html_text = rg.render_html_report(m)
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;" in html_text
    assert _external_url_attrs(html_text) == []


def test_html_same_fixed_section_order(tmp_path):
    html_text = rg.render_html_report(_model(tmp_path))
    positions = [html_text.index(h) for h in (
        "1. Engagement", "2. Executive summary", "3. Triage summary",
        "4. Findings detail", "5. Methodology", "6. Appendix",
    )]
    assert positions == sorted(positions)


# --------------------------------------------------------------------- #
# Acceptance gate 3: no hardcoded counts in template code
# --------------------------------------------------------------------- #
_COUNT_LITERAL = re.compile(
    r"\b\d+\s+(?:finding|findings|total|critical|high|medium|low|servers?|"
    r"files)\b|\bP[0-3]\s*[:=]\s*\d", re.IGNORECASE)


def test_no_hardcoded_counts_in_template_code():
    """Every number in the rendered report must trace to scan-JSON data:
    grep every string literal in the generator module for count-shaped
    literals."""
    src = Path(rg.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _COUNT_LITERAL.search(node.value):
                offenders.append((node.lineno, node.value[:60]))
    assert offenders == [], f"count-shaped literals in template code: {offenders}"


def test_generator_module_is_ascii_only():
    Path(rg.__file__).read_text(encoding="utf-8").encode("ascii")
