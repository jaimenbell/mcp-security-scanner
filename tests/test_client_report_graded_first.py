"""A client report must not LEAD with an ungraded regex hit.

Rendering a TypeScript MCP server after the grading pass landed exposed two
framing gaps that the per-finding UNGRADED badge alone does not close. A
reader's attention goes to the executive summary and "Top 3 to fix" -- and
both were still ranking and describing findings as though every one carried
equal evidence.

1. "Top 3 to fix" ordered by severity alone, so an UNGRADED pattern hit could
   outrank a call-graph-graded finding of the same severity and become the
   first thing a client reads. Graded findings now sort first WITHIN a
   severity tier; severity still dominates, so a graded P2 never jumps a P0.

2. The executive summary asserted "Each critical below includes a reproducible
   proof you can check yourself" even when there were zero criticals, and said
   nothing about how much of the finding set was ungraded.
"""
from pathlib import Path

import pytest

from mcp_scanner.client_report import render_client_report
from mcp_scanner.models import (Confidence, Finding, Grade, Reachability,
                                ScanResult, Severity)


def _f(vuln_class, file, line, severity, grade, title="t"):
    return Finding(
        vuln_class=vuln_class, title=title, severity=severity,
        confidence=Confidence.LOW, file=file, line=line,
        detail=f"detail for {file}:{line}", remediation="fix it",
        grade=grade,
        reachability=(Reachability.CLI_ONLY if grade is Grade.GRADED
                      else Reachability.UNKNOWN),
    )


def test_graded_findings_lead_the_top_3_within_a_severity_tier():
    """Both entries are P2, so severity cannot be doing the sorting -- only
    the grade can. The graded one must come first."""
    r = ScanResult(target="/x", files_scanned=2)
    r.findings = [
        _f("ssrf", "a_ungraded.ts", 10, Severity.P2, Grade.UNGRADED),
        _f("ssrf", "z_graded.py", 20, Severity.P2, Grade.GRADED),
    ]
    md = render_client_report(r)
    top3 = md.split("## 2. Top 3 to fix")[1].split("## 3.")[0]
    assert top3.index("z_graded.py") < top3.index("a_ungraded.ts"), (
        "a graded finding must outrank an ungraded one of the same severity; "
        "filename order (a_ before z_) is deliberately the opposite so this "
        "cannot pass by accident"
    )


def test_severity_still_dominates_the_grade():
    """SCOPE PIN. Grade is a tiebreaker WITHIN a severity tier, never a
    reordering across tiers -- an ungraded P0 still outranks a graded P2."""
    r = ScanResult(target="/x", files_scanned=2)
    r.findings = [
        _f("ssrf", "low_but_graded.py", 20, Severity.P2, Grade.GRADED),
        _f("code-eval", "high_but_ungraded.ts", 10, Severity.P0, Grade.UNGRADED),
    ]
    md = render_client_report(r)
    top3 = md.split("## 2. Top 3 to fix")[1].split("## 3.")[0]
    assert top3.index("high_but_ungraded.ts") < top3.index("low_but_graded.py")


def test_executive_summary_states_the_ungraded_share():
    r = ScanResult(target="/x", files_scanned=2)
    r.findings = [
        _f("ssrf", "a.ts", 10, Severity.P2, Grade.UNGRADED),
        _f("ssrf", "b.ts", 11, Severity.P2, Grade.UNGRADED),
        _f("ssrf", "c.py", 12, Severity.P2, Grade.GRADED),
    ]
    md = render_client_report(r)
    summary = md.split("## 1. Executive summary")[1].split("## 2.")[0]
    assert "2 of the 3" in summary and "ungraded" in summary.lower()


def test_no_critical_proof_claim_when_there_are_no_criticals():
    """The claim 'each critical includes a reproducible proof' is true and
    worth making -- but only when criticals exist. Asserted in both
    directions so it cannot be fixed by deleting the sentence outright."""
    r = ScanResult(target="/x", files_scanned=1)
    r.findings = [_f("ssrf", "a.ts", 10, Severity.P2, Grade.UNGRADED)]
    summary = render_client_report(r).split("## 1. Executive summary")[1]
    assert "Each critical below includes a reproducible proof" not in summary

    r2 = ScanResult(target="/x", files_scanned=1)
    r2.findings = [_f("code-eval", "a.py", 10, Severity.P0, Grade.GRADED)]
    summary2 = render_client_report(r2).split("## 1. Executive summary")[1]
    assert "Each critical below includes a reproducible proof" in summary2
