"""Golden-file renders (acceptance gate 1, spec 2026-07-23).

Full HTML + Markdown renders for a fixture scan, byte-stable given fixed
inputs (modulo git newline normalization -- both sides are read through
universal newlines). Cases: with annotations, without annotations, empty
scan, unknown-annotation-id.

To regenerate after an INTENTIONAL template change:
    py -3.12 tests/fixtures/report_golden/regen.py
then review the diff -- a golden change must always be a reviewed diff,
never a silent side effect.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scanner import report_generator as rg

GOLDEN = Path(__file__).parent / "fixtures" / "report_golden"

CASES = [
    ("with_annotations", "scan.json", "triage.toml"),
    ("without_annotations", "scan.json", None),
    ("empty", "scan_empty.json", None),
    ("unknown_id", "scan.json", "triage_unknown.toml"),
]


def _render(scan_name: str, triage_name: "str | None") -> tuple[str, str]:
    scan = rg.load_scan(GOLDEN / scan_name)
    ann = rg.load_annotations(GOLDEN / triage_name) if triage_name else {}
    model = rg.build_report_model(
        scan, ann,
        client="Acme Corp", engagement="Week-1 Audit", scope="1 MCP server",
        annotations_name=triage_name or "",
    )
    return rg.render_markdown_report(model), rg.render_html_report(model)


@pytest.mark.parametrize("case,scan_name,triage_name", CASES)
def test_markdown_matches_golden(case, scan_name, triage_name):
    md, _ = _render(scan_name, triage_name)
    expected = (GOLDEN / f"{case}.md").read_text(encoding="utf-8")
    assert md == expected


@pytest.mark.parametrize("case,scan_name,triage_name", CASES)
def test_html_matches_golden(case, scan_name, triage_name):
    _, html_text = _render(scan_name, triage_name)
    expected = (GOLDEN / f"{case}.html").read_text(encoding="utf-8")
    assert html_text == expected


def test_renders_are_deterministic():
    """Same inputs, same output -- twice in one process."""
    assert _render("scan.json", "triage.toml") == _render("scan.json", "triage.toml")
