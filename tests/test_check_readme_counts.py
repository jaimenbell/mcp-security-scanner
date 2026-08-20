"""Unit tests for scripts/check_readme_counts.py -- the CI count-verification
gate. Exercises the pure functions (parse claimed counts, parse actual counts,
compare) without invoking a real pytest subprocess, so these tests are fast and
deterministic.

Covers claimed-matches-actual, claimed-drifts, and claim-missing for BOTH claim
classes the gate now checks (pytest counts and JS/TS detector parity) across
all THREE docs it now covers (README.md, PRODUCT.md, ANNOUNCEMENT.md).

POSITIVE CONTROL (2026-08-20). Per the house rule that a check must be shown to
FIRE on a known-bad input and STAY SILENT on a known-good one, in the same
commit: `test_gate_fires_on_*` doctor a real claim and assert the gate goes red;
`test_real_repo_docs_*` run against the REAL checked-in docs and the REAL
detector source and assert it stays green. The real-docs controls deliberately
pin NO churning literal -- they assert README and ANNOUNCEMENT agree with each
OTHER, and that the parity claims agree with the detector source -- so adding
tests (including these) can never make them stale. CI still checks the absolute
numbers against a real junit.xml at build time.
"""
from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "check_readme_counts.py"
_spec = importlib.util.spec_from_file_location("check_readme_counts", _SCRIPT_PATH)
check_readme_counts = importlib.util.module_from_spec(_spec)
sys.modules["check_readme_counts"] = check_readme_counts
_spec.loader.exec_module(check_readme_counts)


# ---------------------------------------------------------------------------
# parse_claimed_counts -- anchored to the real README phrasing:
#   "# 771 tests (762 passing, 9 self-audit skip without the env var below)"
# ---------------------------------------------------------------------------

def test_parse_claimed_counts_matches_real_phrasing():
    readme = textwrap.dedent(
        """
        ```bash
        python -m pytest -q     # 162 tests (155 passing, 7 self-audit skip without the env var below): stuff
        ```
        """
    )
    claim = check_readme_counts.parse_claimed_counts(readme)
    assert claim == check_readme_counts.Counts(total=162, passed=155, skipped=7)


def test_parse_claimed_counts_missing_claim_returns_none():
    readme = "# mcp-security-scanner\n\nNo test count mentioned anywhere in here.\n"
    assert check_readme_counts.parse_claimed_counts(readme) is None


def test_parse_claimed_counts_ignores_unrelated_numbers():
    readme = "This scanner covers 7 detector families across 6 real servers.\n"
    assert check_readme_counts.parse_claimed_counts(readme) is None


# ---------------------------------------------------------------------------
# parse_announcement_counts -- the SAME fact, a different sentence shape
# ---------------------------------------------------------------------------

def test_parse_announcement_counts_matches_real_phrasing():
    text = textwrap.dedent(
        """
        771 tests total (`python -m pytest -q`) - 762 pass by default, 9 fleet
        self-audit tests skip without `MCP_SCANNER_FLEET_ROOT` set.
        """
    )
    claim = check_readme_counts.parse_announcement_counts(text)
    assert claim == check_readme_counts.Counts(total=771, passed=762, skipped=9)


def test_parse_announcement_counts_missing_returns_none():
    assert check_readme_counts.parse_announcement_counts("no counts here\n") is None


# ---------------------------------------------------------------------------
# JS/TS parity counting
# ---------------------------------------------------------------------------

def test_as_int_accepts_words_and_digits():
    assert check_readme_counts._as_int("five") == 5
    assert check_readme_counts._as_int("Five") == 5
    assert check_readme_counts._as_int("5") == 5
    assert check_readme_counts._as_int("bananas") is None


def test_count_js_capable_detectors_counts_only_js_touching_modules(tmp_path):
    det = tmp_path / "detectors"
    det.mkdir()
    (det / "__init__.py").write_text("import js_util  # must be skipped\n", encoding="utf-8")
    (det / "base.py").write_text("import js_util  # must be skipped\n", encoding="utf-8")
    (det / "has_js.py").write_text("from .. import js_util\n", encoding="utf-8")
    (det / "also_js.py").write_text("x = js_util.JS_SUFFIXES\n", encoding="utf-8")
    (det / "python_only.py").write_text("import ast\n", encoding="utf-8")
    assert check_readme_counts.count_js_capable_detectors(det) == 2


def test_compare_parity_match_passes():
    ok, message = check_readme_counts.compare_parity(5, 5, "README.md")
    assert ok is True
    assert "5" in message


def test_compare_parity_drift_fails_and_names_both_numbers():
    ok, message = check_readme_counts.compare_parity(4, 5, "README.md")
    assert ok is False
    assert "4" in message and "5" in message


def test_compare_parity_missing_claim_fails():
    ok, message = check_readme_counts.compare_parity(None, 5, "PRODUCT.md")
    assert ok is False
    assert "could not find" in message.lower()


# ---------------------------------------------------------------------------
# parse_actual_counts -- from a pytest --junitxml report
# ---------------------------------------------------------------------------

_JUNIT_MATCH = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
<testsuite name="pytest" errors="0" failures="0" skipped="7" tests="162" time="1.9">
</testsuite>
</testsuites>
"""

_JUNIT_WITH_FAILURES = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
<testsuite name="pytest" errors="1" failures="2" skipped="7" tests="162" time="1.9">
</testsuite>
</testsuites>
"""


def test_parse_actual_counts_from_junit(tmp_path):
    junit_file = tmp_path / "junit.xml"
    junit_file.write_text(_JUNIT_MATCH, encoding="utf-8")
    actual = check_readme_counts.parse_actual_counts(junit_file)
    assert actual == check_readme_counts.Counts(total=162, passed=155, skipped=7)


def test_parse_actual_counts_subtracts_errors_and_failures(tmp_path):
    junit_file = tmp_path / "junit.xml"
    junit_file.write_text(_JUNIT_WITH_FAILURES, encoding="utf-8")
    actual = check_readme_counts.parse_actual_counts(junit_file)
    # 162 total - 7 skipped - 2 failures - 1 error = 152 passed
    assert actual == check_readme_counts.Counts(total=162, passed=152, skipped=7)


# ---------------------------------------------------------------------------
# compare -- the gate's pass/fail decision
# ---------------------------------------------------------------------------

def test_compare_match_passes():
    counts = check_readme_counts.Counts(total=162, passed=155, skipped=7)
    ok, message = check_readme_counts.compare(counts, counts)
    assert ok is True
    assert "match" in message.lower()


def test_compare_drift_fails():
    claimed = check_readme_counts.Counts(total=162, passed=155, skipped=7)
    actual = check_readme_counts.Counts(total=170, passed=163, skipped=7)
    ok, message = check_readme_counts.compare(claimed, actual)
    assert ok is False
    assert "162" in message and "170" in message


def test_compare_missing_claim_fails():
    ok, message = check_readme_counts.compare(
        None, check_readme_counts.Counts(total=162, passed=155, skipped=7)
    )
    assert ok is False
    assert "could not find" in message.lower()


# ---------------------------------------------------------------------------
# main() end-to-end against synthetic fixture files on disk
# ---------------------------------------------------------------------------

def _write_fixture_repo(tmp_path, *, readme_counts="162 tests (155 passing, 7 self-audit skip",
                        announcement_counts="162 tests total (`python -m pytest -q`) - 155 pass by default, 7 fleet self-audit tests skip",
                        readme_parity="Two", product_parity="Two"):
    """Build a minimal repo shaped like the real one. Defaults are CONSISTENT
    (they match _JUNIT_MATCH and the 2 js_util detectors below), so any single
    doctored argument is the only thing that can turn the gate red."""
    readme = tmp_path / "README.md"
    readme.write_text(
        f"python -m pytest -q     # {readme_counts} without the env var below)\n\n"
        f"{readme_parity} detector families now have JS/TS parity on this regex basis: stuff.\n",
        encoding="utf-8",
    )
    product = tmp_path / "PRODUCT.md"
    product.write_text(
        f"{product_parity} of the six detector families that previously only ran on Python.\n",
        encoding="utf-8",
    )
    announcement = tmp_path / "ANNOUNCEMENT.md"
    announcement.write_text(f"{announcement_counts} without the env var.\n", encoding="utf-8")

    det = tmp_path / "detectors"
    det.mkdir()
    (det / "__init__.py").write_text("\n", encoding="utf-8")
    (det / "a.py").write_text("import js_util\n", encoding="utf-8")
    (det / "b.py").write_text("import js_util\n", encoding="utf-8")
    (det / "c.py").write_text("import ast\n", encoding="utf-8")

    junit = tmp_path / "junit.xml"
    junit.write_text(_JUNIT_MATCH, encoding="utf-8")

    return [
        "--readme", str(readme),
        "--product", str(product),
        "--announcement", str(announcement),
        "--detectors", str(det),
        "--junit-xml", str(junit),
    ]


def test_main_exits_zero_when_everything_agrees(tmp_path):
    assert check_readme_counts.main(_write_fixture_repo(tmp_path)) == 0


# --- POSITIVE CONTROL: the gate must FIRE on each known-bad input -----------

def test_gate_fires_on_readme_count_drift(tmp_path):
    argv = _write_fixture_repo(tmp_path, readme_counts="999 tests (900 passing, 7 self-audit skip")
    assert check_readme_counts.main(argv) == 1


def test_gate_fires_on_announcement_count_drift(tmp_path):
    """The exact class that went unnoticed: ANNOUNCEMENT.md said 439/430
    against a real 771/762 because nothing checked that file."""
    argv = _write_fixture_repo(
        tmp_path,
        announcement_counts="439 tests total (`python -m pytest -q`) - 430 pass by default, 7 fleet self-audit tests skip",
    )
    assert check_readme_counts.main(argv) == 1


def test_gate_fires_on_readme_parity_drift(tmp_path):
    """The exact class that went unnoticed from 2026-07-30 to 2026-08-20:
    the doc said 'four' after a fifth detector gained a JS path."""
    argv = _write_fixture_repo(tmp_path, readme_parity="Four")
    assert check_readme_counts.main(argv) == 1


def test_gate_fires_on_product_parity_drift(tmp_path):
    argv = _write_fixture_repo(tmp_path, product_parity="Four")
    assert check_readme_counts.main(argv) == 1


def test_gate_fires_on_missing_readme_claim(tmp_path):
    argv = _write_fixture_repo(tmp_path)
    Path(argv[1]).write_text("Nothing about test counts or parity here.\n", encoding="utf-8")
    assert check_readme_counts.main(argv) == 1


def test_gate_reports_missing_file_distinctly(tmp_path):
    argv = _write_fixture_repo(tmp_path)
    Path(argv[5]).unlink()  # PRODUCT.md
    assert check_readme_counts.main(argv) == 2


# --- POSITIVE CONTROL: it must STAY SILENT on the REAL, production docs -----

def test_real_repo_docs_agree_with_each_other_on_test_counts():
    """README.md and ANNOUNCEMENT.md must claim the SAME triple as each other.
    Pins no literal, so adding tests can never make this stale -- it catches
    exactly the two-docs-disagree state that shipped for three weeks."""
    readme_claim = check_readme_counts.parse_claimed_counts(
        (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    )
    announcement_claim = check_readme_counts.parse_announcement_counts(
        (_REPO_ROOT / "ANNOUNCEMENT.md").read_text(encoding="utf-8")
    )
    assert readme_claim is not None, "README.md lost its test-count claim"
    assert announcement_claim is not None, "ANNOUNCEMENT.md lost its test-count claim"
    assert readme_claim == announcement_claim


def test_real_repo_parity_claims_match_the_real_detector_source():
    """README.md and PRODUCT.md must both agree with the actual detector code."""
    actual = check_readme_counts.count_js_capable_detectors(_REPO_ROOT / "mcp_scanner" / "detectors")
    readme_match = check_readme_counts.README_PARITY_RE.search(
        (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    )
    product_match = check_readme_counts.PRODUCT_PARITY_RE.search(
        (_REPO_ROOT / "PRODUCT.md").read_text(encoding="utf-8")
    )
    assert readme_match is not None, "README.md lost its JS/TS parity claim"
    assert product_match is not None, "PRODUCT.md lost its JS/TS parity claim"
    assert check_readme_counts._as_int(readme_match.group("count")) == actual
    assert check_readme_counts._as_int(product_match.group("count")) == actual
