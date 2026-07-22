"""Regression tests for the 2026-07-21 fleet self-audit ranked backlog,
items #1 (PowerShell-native destructive-task patterns + benign-register
suppressor), #2 (unverified-success suppressor), #4 (inline-comment-tail
stripping).

Note: 'Stop-Process -Force' and 'Disable-ScheduledTask' were evaluated as
item #1 candidate siblings and deliberately NOT shipped -- see job_hazards.py
_DESTRUCTIVE_PATTERNS comment for the live-regression evidence (both fire on
legitimate fleet code with no real reliability signal).
"""

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import JobHazardsDetector
from mcp_scanner.models import Severity


def _run(fixtures_dir, name):
    return scan_repo(str(fixtures_dir / name), [JobHazardsDetector()])


def _destructive(r):
    return [f for f in r.findings if f.vuln_class == "job-destructive-no-confirm"]


def _unverified(r):
    return [f for f in r.findings if f.vuln_class == "job-unverified-success"]


# --- #1: Unregister-ScheduledTask -Confirm:$false -------------------------

def test_orphan_unregister_flagged(fixtures_dir):
    r = _run(fixtures_dir, "backlog_orphan_unregister")
    hits = _destructive(r)
    assert any(f.file.endswith("decommission.ps1") and f.severity == Severity.P0 for f in hits), \
        [f"{f.file}:{f.line} {f.severity}" for f in hits]


def test_benign_unregister_then_reregister_same_task_not_flagged(fixtures_dir):
    r = _run(fixtures_dir, "backlog_register_pattern")
    hits = _destructive(r)
    assert hits == [], [f"{f.file}:{f.line} {f.title}" for f in hits]


# --- #2: empty-catch suppressed when downstream verifies success ----------

def test_empty_catch_suppressed_when_downstream_verifies(fixtures_dir):
    r = _run(fixtures_dir, "backlog_catch_verified")
    hits = _unverified(r)
    assert hits == [], [f"{f.file}:{f.line} {f.title}" for f in hits]


def test_empty_catch_still_flags_without_verification(fixtures_dir):
    # control: the original vuln_job fixture's bare empty catch (no downstream
    # verification anywhere in the file) must still be caught.
    r = scan_repo(str(fixtures_dir / "vuln_job"), [JobHazardsDetector()])
    hits = _unverified(r)
    assert any(f.file.endswith("deploy.ps1") for f in hits)


# --- #4: inline comment-tail stripped before pattern matching --------------

def test_comment_tail_only_mention_not_flagged(fixtures_dir):
    r = _run(fixtures_dir, "backlog_comment_tail")
    hits = _destructive(r)
    offenders_at_line3 = [f for f in hits if f.line == 3]
    assert offenders_at_line3 == [], [f"{f.file}:{f.line} {f.title}" for f in offenders_at_line3]


def test_real_destructive_with_trailing_comment_still_flags(fixtures_dir):
    r = _run(fixtures_dir, "backlog_comment_tail")
    hits = _destructive(r)
    assert any(f.line == 4 for f in hits), [f"{f.file}:{f.line} {f.title}" for f in hits]


def test_full_comment_line_still_skipped(fixtures_dir):
    r = _run(fixtures_dir, "backlog_comment_tail")
    hits = _destructive(r)
    assert all(f.line != 2 for f in hits), [f"{f.file}:{f.line} {f.title}" for f in hits]
