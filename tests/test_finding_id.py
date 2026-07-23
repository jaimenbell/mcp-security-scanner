"""Stable finding identity (spec: client-report-generator 2026-07-23).

``finding_id`` = short hash of (vuln_class, repo-relative file, normalized
title) -- deliberately EXCLUDING the line number, because lines shift between
re-scans while class+file+title is the stable spine. Collisions within the
same (class, file, title) triple get a ``-2``/``-3``... suffix by original
order. Emitted in scan JSON; used as the triage-annotation key and, later,
the Managed-Watch trending key.
"""
from __future__ import annotations

import json
import re

from mcp_scanner.finding_identity import compute_finding_id, assign_finding_ids
from mcp_scanner.models import ScanResult, Finding, Severity, Confidence
from mcp_scanner.reporting import render_json


def _finding(vuln_class="param-injection", title="shell=True subprocess call",
             file="srv/tools.py", line=10, sev=Severity.P1):
    return Finding(
        vuln_class=vuln_class, title=title, severity=sev,
        confidence=Confidence.HIGH, file=file, line=line,
        detail="detail", remediation="fix it",
    )


# --------------------------------------------------------------------- #
# compute_finding_id
# --------------------------------------------------------------------- #
def test_id_is_short_stable_hex():
    fid = compute_finding_id("param-injection", "srv/tools.py", "a title")
    assert re.fullmatch(r"[0-9a-f]{12}", fid)
    # Deterministic across calls.
    assert fid == compute_finding_id("param-injection", "srv/tools.py", "a title")


def test_id_excludes_line_number_line_shift_keeps_id():
    """Acceptance gate 2: the same finding across a line-shifted re-scan
    keeps its id."""
    before = _finding(line=10)
    after = _finding(line=57)  # same class/file/title, lines shifted
    id_before = compute_finding_id(before.vuln_class, before.file, before.title)
    id_after = compute_finding_id(after.vuln_class, after.file, after.title)
    assert id_before == id_after


def test_id_changes_with_class_file_or_title():
    base = compute_finding_id("c", "f.py", "t")
    assert compute_finding_id("c2", "f.py", "t") != base
    assert compute_finding_id("c", "g.py", "t") != base
    assert compute_finding_id("c", "f.py", "t2") != base


def test_title_is_normalized_case_and_whitespace():
    a = compute_finding_id("c", "f.py", "Hardcoded  Secret\tassignment")
    b = compute_finding_id("c", "f.py", "hardcoded secret assignment")
    assert a == b


# --------------------------------------------------------------------- #
# assign_finding_ids (collision handling)
# --------------------------------------------------------------------- #
def test_collisions_get_numeric_suffix_by_original_order():
    triples = [
        ("c", "f.py", "same title"),
        ("c", "f.py", "same title"),
        ("c", "other.py", "same title"),
        ("c", "f.py", "same title"),
    ]
    ids = assign_finding_ids(triples)
    base = compute_finding_id("c", "f.py", "same title")
    other = compute_finding_id("c", "other.py", "same title")
    assert ids == [base, f"{base}-2", other, f"{base}-3"]


def test_no_collision_no_suffix():
    ids = assign_finding_ids([("c", "a.py", "t1"), ("c", "b.py", "t2")])
    assert all("-" not in i for i in ids)


# --------------------------------------------------------------------- #
# scan JSON emission (regression-guarded: existing keys unchanged)
# --------------------------------------------------------------------- #
def test_scan_json_emits_finding_id_per_finding():
    r = ScanResult(target="repo")
    r.add(_finding(line=3))
    r.add(_finding(line=99))  # collision with the first (same class/file/title)
    data = json.loads(render_json(r))
    ids = [f["finding_id"] for f in data["findings"]]
    assert len(ids) == 2
    assert ids[0] != ids[1]
    assert ids[1] == ids[0] + "-2"


def test_scan_json_existing_keys_unchanged_regression():
    """Any touch to scan-JSON emission gets a regression test (lane rail):
    all pre-existing keys stay present with unchanged values."""
    r = ScanResult(target="repo", files_scanned=5)
    r.add(_finding())
    data = json.loads(render_json(r))
    for key in ("target", "files_scanned", "counts_by_severity", "clean_bill",
                "findings", "errors"):
        assert key in data
    f = data["findings"][0]
    for key in ("vuln_class", "title", "severity", "confidence", "file",
                "line", "detail", "remediation", "snippet", "reachability",
                "reachability_evidence", "taint"):
        assert key in f
    assert f["severity"] == "P1"
    assert f["confidence"] == "high"
    assert data["clean_bill"] is False
