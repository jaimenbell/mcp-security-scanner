"""Client-facing report rendering.

Voice mirrors the reliability-retainer's honest-engineering framing: no
fear-selling, an explicit capability boundary, every finding carries a
confidence so the client can triage. A clean result says so plainly.
"""

from __future__ import annotations

import json

from .models import ScanResult, Severity, Confidence

_BOUNDARY = (
    "This is a **static** analysis. It flags risky patterns and surfaces by "
    "reading source; it does not run the server and does not prove that any "
    "finding is remotely exploitable. Treat findings as a prioritized review "
    "queue, not a verdict. A clean bill means no critical/high patterns were "
    "found by these detectors -- not a guarantee of security."
)


def render_markdown(result: ScanResult) -> str:
    counts = result.counts_by_severity()
    lines: list[str] = []
    lines.append(f"# MCP Server Security Scan -- `{_short(result.target)}`")
    lines.append("")
    if result.clean_bill:
        lines.append("> [!success] Clean bill of health")
        lines.append(f"> No critical (P0) or high (P1) findings across "
                     f"{result.files_scanned} source files. "
                     f"{counts['P2']} medium and {counts['P3']} low informational "
                     f"notes below.")
    else:
        lines.append("> [!warning] Action recommended")
        lines.append(f"> {counts['P0']} critical, {counts['P1']} high, "
                     f"{counts['P2']} medium, {counts['P3']} low across "
                     f"{result.files_scanned} source files.")
    lines.append("")
    lines.append("> [!info] Capability boundary")
    lines.append(f"> {_BOUNDARY}")
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
            lines.append(f"### {i}. [{f.severity.value}] {f.title}  \n"
                         f"*{f.severity.label} | confidence: {f.confidence.value} | "
                         f"reachable: {f.reachability.value} | "
                         f"taint: {f.taint.value} | "
                         f"class: `{f.vuln_class}` | {loc}*")
            lines.append("")
            lines.append(f"- **What:** {f.detail}")
            if f.snippet:
                lines.append(f"- **Where:** `{f.snippet}`")
            lines.append(f"- **Fix:** {f.remediation}")
            lines.append("")

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
    return (f"{verdict:8} {_short(result.target):40} "
            f"P0={c['P0']} P1={c['P1']} P2={c['P2']} P3={c['P3']} "
            f"({result.files_scanned} files)")


def _short(path: str) -> str:
    p = path.replace("\\", "/")
    return p.rsplit("/", 1)[-1] or p
