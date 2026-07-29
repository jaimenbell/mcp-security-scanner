"""Client-facing report rendering.

Voice mirrors the reliability-retainer's honest-engineering framing: no
fear-selling, an explicit capability boundary, every finding carries a
confidence so the client can triage. A clean result says so plainly.
"""

from __future__ import annotations

import json

from .models import Grade, ScanResult, Severity, Confidence

_BOUNDARY = (
    "This is a **static** analysis. It flags risky patterns and surfaces by "
    "reading source; it does not run the server and does not prove that any "
    "finding is remotely exploitable. Treat findings as a prioritized review "
    "queue, not a verdict. A clean bill means no critical/high patterns were "
    "found by these detectors -- not a guarantee of security."
)

# Rendered next to every ungraded finding. The 2026-07-29 measurement's core
# product defect was that a regex hit and a call-graph-proven finding looked
# identical in the report; this marker is what makes them not.
_UNGRADED_BADGE = "**UNGRADED**"
_UNGRADED_LEGEND = (
    "**UNGRADED** marks a finding that the reachability and dataflow passes "
    "could not analyse at all -- it is a pattern match and nothing more. It "
    "has not been shown to be reachable from any registered MCP tool, and no "
    "check was made for a validator or sanitiser next to the flagged line. "
    "Triage these by reading the code; do not treat the severity as evidence."
)


def _ungraded(result: ScanResult) -> list:
    return [f for f in result.findings if f.grade is Grade.UNGRADED]


def _render_coverage(result: ScanResult) -> list[str]:
    """The per-run 'what could you not grade, and why?' section."""
    cov = result.coverage
    if not cov:
        return []
    lines = ["## Grading coverage", ""]
    lines.append(f"- Files the precision passes could analyse: "
                 f"**{cov.get('gradable_files', 0)}**")
    lines.append(f"- Files they could not: **{cov.get('ungradable_files', 0)}**")
    lines.append(f"- Findings graded: **{cov.get('findings_graded', 0)}** | "
                 f"ungraded: **{cov.get('findings_ungraded', 0)}**")
    reasons = cov.get("ungradable_files_by_reason") or {}
    if reasons:
        lines.append("")
        lines.append("| Files | Reason they could not be graded |")
        lines.append("|---|---|")
        for reason, count in reasons.items():
            lines.append(f"| {count} | {reason} |")
    lines.append("")
    # The legend is only printed when there is something ungraded to explain.
    # Printing it on a fully-graded scan would train readers to skip it, and
    # this warning has to still land on the scan where it matters.
    if cov.get("findings_ungraded") or cov.get("ungradable_files"):
        lines.append(f"> {_UNGRADED_LEGEND}")
        lines.append("")
    return lines


def render_markdown(result: ScanResult) -> str:
    counts = result.counts_by_severity()
    lines: list[str] = []
    lines.append(f"# MCP Server Security Scan -- `{_short(result.target)}`")
    lines.append("")
    ungraded = _ungraded(result)
    n_ungradable_files = (result.coverage or {}).get("ungradable_files", 0)
    if result.clean_bill:
        lines.append("> [!success] Clean bill of health")
        lines.append(f"> No critical (P0) or high (P1) findings across "
                     f"{result.files_scanned} source files. "
                     f"{counts['P2']} medium and {counts['P3']} low informational "
                     f"notes below.")
        # The mirror-image failure mode: a clean bill over a surface we could
        # not analyse is a FALSE assurance. It has to be qualified in the same
        # callout, not buried further down where nobody reads it.
        if n_ungradable_files:
            lines.append(f"> **Scope caveat:** {n_ungradable_files} of "
                         f"{result.files_scanned} files could not be graded "
                         "for reachability or dataflow (see Grading coverage "
                         "below). This clean bill covers the graded surface "
                         "only.")
    else:
        lines.append("> [!warning] Action recommended")
        lines.append(f"> {counts['P0']} critical, {counts['P1']} high, "
                     f"{counts['P2']} medium, {counts['P3']} low across "
                     f"{result.files_scanned} source files.")
    lines.append("")
    lines.append("> [!info] Capability boundary")
    lines.append(f"> {_BOUNDARY}")
    if ungraded:
        lines.append(f"> ")
        lines.append(f"> {len(ungraded)} of {len(result.findings)} findings "
                     f"below are {_UNGRADED_BADGE}. {_UNGRADED_LEGEND}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for s in Severity:
        lines.append(f"| {s.value} ({s.label}) | {counts[s.value]} |")
    lines.append("")

    findings = result.sorted_findings
    if not findings:
        lines.append("No findings. Nothing to remediate from this pass.")
    else:
        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, start=1):
            loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
            badge = f"{_UNGRADED_BADGE} " if f.grade is Grade.UNGRADED else ""
            lines.append(f"### {i}. [{f.severity.value}] {badge}{f.title}  \n"
                         f"*{f.severity.label} | confidence: {f.confidence.value} | "
                         f"grade: {f.grade.value} | "
                         f"reachable: {f.reachability.value} | "
                         f"taint: {f.taint.value} | "
                         f"class: `{f.vuln_class}` | {loc}*")
            lines.append("")
            lines.append(f"- **What:** {f.detail}")
            if f.snippet:
                lines.append(f"- **Where:** `{f.snippet}`")
            if f.grade_reason:
                lines.append(f"- **Not graded because:** {f.grade_reason}")
            if f.reachability_evidence:
                lines.append(f"- **Reachability evidence:** {f.reachability_evidence}")
            lines.append(f"- **Fix:** {f.remediation}")
            lines.append("")

    lines.extend(_render_coverage(result))

    if result.errors:
        lines.append("## Scan notes")
        lines.append("")
        for e in result.errors:
            lines.append(f"- {e}")
        lines.append("")

    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_summary_line(result: ScanResult) -> str:
    c = result.counts_by_severity()
    verdict = "CLEAN" if result.clean_bill else "FINDINGS"
    n_ungraded = len(_ungraded(result))
    return (f"{verdict:8} {_short(result.target):40} "
            f"P0={c['P0']} P1={c['P1']} P2={c['P2']} P3={c['P3']} "
            f"ungraded={n_ungraded} "
            f"({result.files_scanned} files)")


def _short(path: str) -> str:
    p = path.replace("\\", "/")
    return p.rsplit("/", 1)[-1] or p
