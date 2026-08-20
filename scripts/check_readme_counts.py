#!/usr/bin/env python3
"""CI count-verification gate.

Fails the build if a claimed number in a public doc drifts from what the real
artifact reports. Generalizes the proof-manifest pattern -- a claimed number in
a public doc must be provable against the thing it describes, every run, or the
build goes red.

Stdlib-only by design (no new test/CI dependency).

SCOPE (stated with the pattern, deliberately -- 2026-08-20)
-----------------------------------------------------------
A gate is two things: what it matches and WHERE it applies. This one used to
check pytest counts in README.md only, while its own failure message told the
reader to "also update PRODUCT.md/ANNOUNCEMENT.md if they carry the same
claim". They did carry it, nothing checked them, and all three drifted:

  * ANNOUNCEMENT.md claimed 439 tests / 430 passing against a real 771 / 762 --
    stale by 332 tests.
  * README.md and PRODUCT.md claimed "four detector families have JS/TS parity"
    after auth_posture gained a JS path on 2026-07-30, making the real count
    five. Stale for three weeks, contradicted by README's own changelog.

So this gate now covers THREE docs and TWO claim classes:

  1. pytest counts        -- README.md, ANNOUNCEMENT.md   (vs --junit-xml)
  2. JS/TS parity count   -- README.md, PRODUCT.md        (vs the detector source)

What it still does NOT cover, so the next reader knows the edge: any other
number in any other file, and prose claims that carry no digit. Widen it here
rather than adding a second gate.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# --- claim 1: pytest counts -------------------------------------------------

# README phrasing this anchors to (see README.md, "Tests" section):
#     python -m pytest -q     # 771 tests (762 passing, 9 self-audit skip ...)
# i.e. "# <total> tests (<passed> passing, <skipped> self-audit skip".
README_COUNT_RE = re.compile(
    r"#\s*(?P<total>\d+)\s+tests\s+\((?P<passed>\d+)\s+passing,\s+(?P<skipped>\d+)\s+self-audit skip"
)

# ANNOUNCEMENT.md phrasing (a DIFFERENT sentence shape for the same fact):
#     771 tests total (`python -m pytest -q`) - 762 pass by default, 9 fleet
#     self-audit tests skip without `MCP_SCANNER_FLEET_ROOT` set.
# Newline-tolerant: the real file wraps between "9 fleet" and "self-audit".
ANNOUNCEMENT_COUNT_RE = re.compile(
    r"(?P<total>\d+)\s+tests\s+total\b.{0,80}?(?P<passed>\d+)\s+pass\s+by\s+default,\s+"
    r"(?P<skipped>\d+)\s+fleet\s+self-audit\s+tests\s+skip",
    re.DOTALL,
)

# --- claim 2: JS/TS detector parity ----------------------------------------

_WORD_NUM = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
    "five": 5, "six": 6, "seven": 7, "eight": 8,
}

# README: "Five detector families now have JS/TS parity on this regex basis:"
README_PARITY_RE = re.compile(
    r"(?P<count>[A-Za-z]+|\d+)\s+detector\s+families\s+now\s+have\s+JS/TS\s+parity",
    re.IGNORECASE,
)

# PRODUCT: "Five of the six detector families that previously only ran on Python"
PRODUCT_PARITY_RE = re.compile(
    r"(?P<count>[A-Za-z]+|\d+)\s+of\s+the\s+(?P<denom>[A-Za-z]+|\d+)\s+detector\s+families",
    re.IGNORECASE,
)


def _as_int(token: str) -> Optional[int]:
    """Accept either a digit ('5') or an English word ('five')."""
    if token.isdigit():
        return int(token)
    return _WORD_NUM.get(token.lower())


@dataclass(frozen=True)
class Counts:
    total: int
    passed: int
    skipped: int


def parse_claimed_counts(readme_text: str) -> Optional[Counts]:
    """Extract the claimed (total, passed, skipped) triple from README text.
    Returns None if the anchored phrasing isn't found -- a missing/renamed
    claim is a gate failure, not a silent pass."""
    return _counts_from(README_COUNT_RE, readme_text)


def parse_announcement_counts(text: str) -> Optional[Counts]:
    """Same fact, ANNOUNCEMENT.md's different sentence shape."""
    return _counts_from(ANNOUNCEMENT_COUNT_RE, text)


def _counts_from(pattern: re.Pattern[str], text: str) -> Optional[Counts]:
    match = pattern.search(text)
    if not match:
        return None
    return Counts(
        total=int(match.group("total")),
        passed=int(match.group("passed")),
        skipped=int(match.group("skipped")),
    )


def parse_actual_counts(junit_xml_path: Path) -> Counts:
    """Extract (total, passed, skipped) from a pytest --junitxml report.
    passed = tests - failures - errors - skipped."""
    tree = ET.parse(junit_xml_path)
    root = tree.getroot()
    # pytest's junit_family=xunit2 (the default) wraps <testsuite> in
    # <testsuites>; handle both shapes.
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise ValueError(f"no <testsuite> element found in {junit_xml_path}")

    total = int(suite.get("tests", 0))
    skipped = int(suite.get("skipped", 0))
    failures = int(suite.get("failures", 0))
    errors = int(suite.get("errors", 0))
    passed = total - skipped - failures - errors
    return Counts(total=total, passed=passed, skipped=skipped)


def count_js_capable_detectors(detectors_dir: Path) -> int:
    """How many detector modules actually carry a JS/TS code path.

    Mechanical proxy: a detector module that references ``js_util`` has one;
    one that never mentions it cannot. Verified 2026-08-20 against the real
    tree -- auth_posture/param_injection/secret_handling/secret_leak_response/
    tool_scope_creep reference it, codegen_injection/job_hazards do not.

    Stated limit: an import added but never used would count as covered. That
    is a smaller risk than the three-week silent drift this gate exists to
    catch, and it fails in the direction of a LOUD mismatch, not a quiet pass.
    """
    skip = {"__init__.py", "base.py"}
    return sum(
        1
        for path in sorted(detectors_dir.glob("*.py"))
        if path.name not in skip and "js_util" in path.read_text(encoding="utf-8")
    )


def compare(claimed: Optional[Counts], actual: Counts, doc: str = "README.md") -> tuple[bool, str]:
    """Decide pass/fail and produce a clear human-readable message."""
    if claimed is None:
        return False, (
            f"COULD NOT FIND a claimed test count in {doc} matching the "
            "expected phrasing. Either the wording changed (update the "
            "matching regex in scripts/check_readme_counts.py in the SAME "
            "commit) or the claim was removed by accident."
        )
    if claimed == actual:
        return True, (
            f"{doc}: test-count claim matches the suite: "
            f"{actual.total} tests ({actual.passed} passing, {actual.skipped} skipped)."
        )
    return False, (
        f"{doc}: test-count claim has DRIFTED from the actual suite:\n"
        f"  {doc} claims : {claimed.total} tests "
        f"({claimed.passed} passing, {claimed.skipped} skipped)\n"
        f"  actual suite : {actual.total} tests "
        f"({actual.passed} passing, {actual.skipped} skipped)"
    )


def compare_parity(claimed: Optional[int], actual: int, doc: str) -> tuple[bool, str]:
    if claimed is None:
        return False, (
            f"COULD NOT FIND a JS/TS parity detector-family count in {doc}. "
            "Either the wording changed (update the matching regex in "
            "scripts/check_readme_counts.py in the SAME commit) or the claim "
            "was removed by accident."
        )
    if claimed == actual:
        return True, f"{doc}: JS/TS parity claim matches the source: {actual} detector families."
    return False, (
        f"{doc}: JS/TS parity claim has DRIFTED from the detector source:\n"
        f"  {doc} claims : {claimed} detector families with a JS/TS path\n"
        f"  actual source: {actual} (detector modules referencing js_util)\n"
        "This is the exact drift that went unnoticed from 2026-07-30 to "
        "2026-08-20 when auth_posture gained a JS path."
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readme", default="README.md", help="path to README.md")
    parser.add_argument("--product", default="PRODUCT.md", help="path to PRODUCT.md")
    parser.add_argument(
        "--announcement", default="ANNOUNCEMENT.md", help="path to ANNOUNCEMENT.md"
    )
    parser.add_argument(
        "--detectors", default="mcp_scanner/detectors", help="path to the detectors package"
    )
    parser.add_argument(
        "--junit-xml", default="junit.xml", help="path to a pytest --junitxml report"
    )
    args = parser.parse_args(argv)

    readme_path = Path(args.readme)
    product_path = Path(args.product)
    announcement_path = Path(args.announcement)
    detectors_dir = Path(args.detectors)
    junit_path = Path(args.junit_xml)

    for label, path in (
        ("README", readme_path),
        ("PRODUCT", product_path),
        ("ANNOUNCEMENT", announcement_path),
        ("junitxml report", junit_path),
    ):
        if not path.exists():
            print(f"ERROR: {label} not found at {path}", file=sys.stderr)
            return 2
    if not detectors_dir.is_dir():
        print(f"ERROR: detectors package not found at {detectors_dir}", file=sys.stderr)
        return 2

    actual_counts = parse_actual_counts(junit_path)
    actual_parity = count_js_capable_detectors(detectors_dir)

    readme_text = readme_path.read_text(encoding="utf-8")
    product_text = product_path.read_text(encoding="utf-8")
    announcement_text = announcement_path.read_text(encoding="utf-8")

    readme_parity_match = README_PARITY_RE.search(readme_text)
    product_parity_match = PRODUCT_PARITY_RE.search(product_text)

    results = [
        compare(parse_claimed_counts(readme_text), actual_counts, "README.md"),
        compare(parse_announcement_counts(announcement_text), actual_counts, "ANNOUNCEMENT.md"),
        compare_parity(
            _as_int(readme_parity_match.group("count")) if readme_parity_match else None,
            actual_parity,
            "README.md",
        ),
        compare_parity(
            _as_int(product_parity_match.group("count")) if product_parity_match else None,
            actual_parity,
            "PRODUCT.md",
        ),
    ]

    for ok, message in results:
        print(("OK   " if ok else "FAIL ") + message)

    failed = [m for ok, m in results if not ok]
    if failed:
        print(
            f"\n{len(failed)} of {len(results)} count claims are wrong. "
            "Fix the doc, or fix this gate in the same commit if the real "
            "number changed.",
            file=sys.stderr,
        )
        return 1
    print(f"\nAll {len(results)} count claims verified against real artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
