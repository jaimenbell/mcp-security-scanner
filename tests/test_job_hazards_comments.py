"""Regression: job-hazards must not flag patterns inside full-comment lines.

Sourced from the 2026-07-21 fleet self-audit sweep: 8 of 9 real fleet
false-positives were destructive/scope patterns matched inside comment lines
(`#` in .sh/.ps1, `REM`/`::` in .cmd) -- documentation and safety-tool pattern
lists, never executed. A destructive call that only appears in a comment is
not a hazard; suppressing it is a pure-precision win with zero recall cost.
"""

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import JobHazardsDetector


def _job(r):
    return [f for f in r.findings if f.vuln_class.startswith("job-")]


def test_comment_only_destructive_lines_not_flagged(fixtures_dir):
    r = scan_repo(str(fixtures_dir / "comment_job"), [JobHazardsDetector()])
    offenders = [f"{f.file}:{f.line} {f.vuln_class}" for f in _job(r)]
    assert offenders == [], f"comment lines should not flag: {offenders}"


def test_real_code_still_flags(fixtures_dir):
    # control: the vuln_job fixture's REAL (non-comment) destructive calls
    # must still be caught -- the fix must not suppress live code.
    r = scan_repo(str(fixtures_dir / "vuln_job"), [JobHazardsDetector()])
    assert _job(r), "real destructive code must still be flagged"
