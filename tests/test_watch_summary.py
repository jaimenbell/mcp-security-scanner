"""Egress-safety tests for the counts-only watch summary (spec gate G5).

The watch_summary module builds the ONLY payload the Managed MCP Watch
Action may ever transmit off a client machine. These tests assert, against
a real scan of a known-vulnerable fixture, that the payload contains
counts/metadata ONLY -- no file paths, no snippets, no finding titles,
no detail prose, no remediation text.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_scanner.scanner import scan_repo
from mcp_scanner.watch_summary import ALLOWED_KEYS, build_counts_payload

FIXTURES = Path(__file__).parent / "fixtures"
VULN_FIXTURE = FIXTURES / "vuln_codegen"
CLEAN_FIXTURE = FIXTURES / "clean_codegen"


@pytest.fixture(scope="module")
def vuln_scan_dict():
    return scan_repo(str(VULN_FIXTURE)).to_dict()


@pytest.fixture(scope="module")
def clean_scan_dict():
    return scan_repo(str(CLEAN_FIXTURE)).to_dict()


def test_payload_keys_are_exactly_the_allowlist(vuln_scan_dict):
    payload = build_counts_payload(vuln_scan_dict, repo="acme/mcp-server",
                                   commit="abc1234")
    assert set(payload.keys()) == ALLOWED_KEYS


def test_payload_has_no_findings_list(vuln_scan_dict):
    payload = build_counts_payload(vuln_scan_dict, repo="acme/mcp-server",
                                   commit="abc1234")
    assert "findings" not in payload
    # No nested list/dict values at all except the severity histogram.
    for key, value in payload.items():
        if key == "counts_by_severity":
            assert isinstance(value, dict)
            assert set(value.keys()) == {"P0", "P1", "P2", "P3"}
            assert all(isinstance(v, int) for v in value.values())
        else:
            assert isinstance(value, (str, int, bool)), (
                f"non-scalar value under {key!r}: {type(value)}"
            )


def test_payload_contains_no_source_material(vuln_scan_dict):
    """The G5 gate: serialize the payload and assert nothing from any
    finding body (path, snippet, title, detail, remediation) leaks in."""
    findings = vuln_scan_dict["findings"]
    assert findings, "fixture must actually produce findings for this test"
    serialized = json.dumps(
        build_counts_payload(vuln_scan_dict, repo="acme/mcp-server",
                             commit="abc1234")
    )
    for f in findings:
        for field in ("file", "snippet", "title", "detail", "remediation"):
            value = f.get(field, "")
            if value:
                # Compare escaped-to-escaped: a raw Windows path (C:\x) never
                # substring-matches its json.dumps form (C:\\x), so a naive
                # `value not in serialized` false-PASSes on backslash paths
                # (found by the 2026-07-22 egress review). json.dumps(value)
                # [1:-1] is the value exactly as it would appear inside the
                # serialized payload.
                escaped = json.dumps(value)[1:-1]
                assert escaped not in serialized, (
                    f"finding {field!r} leaked into the counts payload: "
                    f"{value!r}"
                )


def test_payload_counts_match_scan(vuln_scan_dict):
    payload = build_counts_payload(vuln_scan_dict, repo="acme/mcp-server",
                                   commit="abc1234")
    assert payload["total_findings"] == len(vuln_scan_dict["findings"])
    assert payload["counts_by_severity"] == vuln_scan_dict["counts_by_severity"]
    assert payload["clean_bill"] == vuln_scan_dict["clean_bill"]
    assert payload["files_scanned"] == vuln_scan_dict["files_scanned"]


def test_payload_carries_identity_metadata(vuln_scan_dict):
    payload = build_counts_payload(vuln_scan_dict, repo="acme/mcp-server",
                                   commit="abc1234")
    assert payload["repo"] == "acme/mcp-server"
    assert payload["commit"] == "abc1234"
    assert payload["scanner_version"]
    assert payload["generated_at"].endswith("Z")


def test_payload_omits_scan_target_path(vuln_scan_dict):
    """The scan dict's `target` is a local filesystem path on the client
    machine -- it must never appear in the payload."""
    serialized = json.dumps(
        build_counts_payload(vuln_scan_dict, repo="acme/mcp-server",
                             commit="abc1234")
    )
    # Escaped-to-escaped comparison -- see the note in
    # test_payload_contains_no_source_material (Windows backslash paths
    # double-escape under json.dumps and evade a raw substring check).
    assert json.dumps(vuln_scan_dict["target"])[1:-1] not in serialized
    assert "target" not in json.loads(serialized)


def test_clean_scan_payload(clean_scan_dict):
    payload = build_counts_payload(clean_scan_dict, repo="acme/mcp-server",
                                   commit="abc1234")
    assert payload["clean_bill"] is True
    assert payload["total_findings"] == 0


def test_cli_builds_payload_from_json_file(tmp_path, vuln_scan_dict):
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(vuln_scan_dict), encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-m", "mcp_scanner.watch_summary",
         "--json-file", str(scan_file),
         "--repo", "acme/mcp-server", "--commit", "abc1234"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert set(payload.keys()) == ALLOWED_KEYS
    assert payload["total_findings"] == len(vuln_scan_dict["findings"])


def test_cli_accepts_utf8_bom_json(tmp_path, vuln_scan_dict):
    """Windows runners commonly produce BOM-prefixed JSON (PowerShell
    Out-File / redirection). The CLI must tolerate it."""
    scan_file = tmp_path / "scan_bom.json"
    scan_file.write_bytes(b"\xef\xbb\xbf"
                          + json.dumps(vuln_scan_dict).encode("utf-8"))
    out = subprocess.run(
        [sys.executable, "-m", "mcp_scanner.watch_summary",
         "--json-file", str(scan_file),
         "--repo", "acme/mcp-server", "--commit", "abc1234"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert out.returncode == 0, out.stderr
    assert set(json.loads(out.stdout).keys()) == ALLOWED_KEYS


def test_cli_rejects_missing_file(tmp_path):
    out = subprocess.run(
        [sys.executable, "-m", "mcp_scanner.watch_summary",
         "--json-file", str(tmp_path / "nope.json"),
         "--repo", "r", "--commit", "c"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert out.returncode != 0
