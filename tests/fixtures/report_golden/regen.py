"""Regenerate the golden report renders after an INTENTIONAL template change.

    py -3.12 tests/fixtures/report_golden/regen.py

Review the resulting diff before committing -- a golden change must always
be a reviewed diff, never a silent side effect.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent))

from mcp_scanner import report_generator as rg  # noqa: E402

CASES = [
    ("with_annotations", "scan.json", "triage.toml"),
    ("without_annotations", "scan.json", None),
    ("empty", "scan_empty.json", None),
    ("unknown_id", "scan.json", "triage_unknown.toml"),
]


def main() -> None:
    for case, scan_name, triage_name in CASES:
        scan = rg.load_scan(HERE / scan_name)
        ann = rg.load_annotations(HERE / triage_name) if triage_name else {}
        model = rg.build_report_model(
            scan, ann,
            client="Acme Corp", engagement="Week-1 Audit",
            scope="1 MCP server", annotations_name=triage_name or "",
        )
        (HERE / f"{case}.md").write_text(
            rg.render_markdown_report(model), encoding="utf-8", newline="\n")
        (HERE / f"{case}.html").write_text(
            rg.render_html_report(model), encoding="utf-8", newline="\n")
        print(f"regenerated {case}.md / {case}.html")


if __name__ == "__main__":
    main()
