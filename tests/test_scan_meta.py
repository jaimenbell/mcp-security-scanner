"""Scan JSON metadata embedding (spec: client-report-generator 2026-07-23).

The report cover reads scanner version (git SHA) + canonical suite counts
FROM the scan JSON's metadata -- so the scan must embed them at scan time.
Presentation-layer addition; regression-guarded alongside test_finding_id's
existing-keys test.
"""
from __future__ import annotations

import json
import re

from mcp_scanner import scan_meta
from mcp_scanner.models import ScanResult
from mcp_scanner.reporting import render_json
from mcp_scanner.scanner import scan_repo


def test_scanner_version_is_nonempty_string():
    v = scan_meta.scanner_version()
    assert isinstance(v, str) and v
    # In this checkout it should be a git short SHA (hex, >= 7 chars);
    # a non-git install falls back to the package version.
    assert re.fullmatch(r"[0-9a-f]{7,40}", v) or v.startswith("0.")


def test_suite_counts_parses_readme_claim():
    counts = scan_meta.suite_counts()
    # This repo's README carries the CI-gated claim, so it must parse here.
    assert counts is not None
    assert set(counts) == {"total", "passed", "skipped"}
    assert counts["total"] == counts["passed"] + counts["skipped"]
    assert counts["passed"] > 0


def test_scan_json_embeds_scan_meta():
    r = ScanResult(target="repo", scan_date="2026-07-23")
    data = json.loads(render_json(r))
    meta = data["scan_meta"]
    assert meta["scanner_version"] == scan_meta.scanner_version()
    assert meta["suite_counts"] == scan_meta.suite_counts()
    assert meta["scan_date"] == "2026-07-23"


def test_scan_repo_sets_scan_date(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    result = scan_repo(str(tmp_path))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", result.scan_date)
