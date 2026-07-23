"""`mcp-scan report` -- the client-grade deliverable.

Turns an existing scan-output JSON plus an optional human triage pass
(triage.toml) into the document a client actually pays for: self-contained
HTML (inline CSS, print-clean) and/or Markdown. The report NEVER re-runs
scans -- it only reads the JSON it is given.

Section order is fixed by the 2026-07-23 spec:

  1. Engagement & scan metadata (cover)
  2. Executive summary
  3. Triage summary (the differentiator: raw vs post-triage)
  4. Findings detail
  5. Methodology & honest capability boundary (from boundaries.py)
  6. Appendix

Rendering machinery is shared with the older ``--client-report`` path
(client_report.py): severity legend, incident language, detector-class
table, and the small text helpers are imported from there rather than
re-implemented, so the two deliverables cannot drift apart on vocabulary.

Every quantitative claim in the output is GENERATED from the scan JSON /
annotations -- no hardcoded counts (tested by grepping this module's string
literals). All untrusted scan content is HTML-escaped.

HARD RAIL -- presentation only: nothing here changes detection logic, and
this module never writes to / executes against a scanned target.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
import tomllib
from pathlib import Path

from .boundaries import CAPABILITY_BOUNDARY
from .client_report import (
    SEVERITY_LEGEND,
    VULN_CLASS_INCIDENT_LANG,
    DETECTOR_CLASS_TABLE,
    _first_sentence,
    _md_cell,
    _short,
)
from .finding_identity import assign_finding_ids

# --------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------- #

VERDICTS = ("confirmed", "false-positive", "accepted-risk", "mitigated")
UNREVIEWED = "unreviewed"

VERDICT_LABEL = {
    "confirmed": "Confirmed",
    "false-positive": "False positive",
    "accepted-risk": "Accepted risk",
    "mitigated": "Mitigated",
    UNREVIEWED: "Unreviewed",
}

_SEVERITIES = ("P0", "P1", "P2", "P3")

# Curated per-vuln-class remediation guidance -- static CONTENT, operator
# may edit freely post-merge. The per-finding `remediation` field from the
# scan stays the specific fix; this is the class-level guidance around it.
REMEDIATION_GUIDANCE: dict[str, str] = {
    "codegen-injection": (
        "Render untrusted input through a real serializer or a template "
        "engine with autoescape enabled -- never hand-rolled string "
        "escaping in a code-generating tool. Treat every value that can "
        "reach generated source as attacker-controlled."
    ),
    "param-injection": (
        "Never pass caller-influenced input to a shell (`shell=True`, "
        "`os.system`), `eval`/`exec`, `pickle.load`, or unsafe `yaml.load`. "
        "Use argv lists for subprocesses, `SafeLoader` for YAML, and "
        "validate/allowlist any path or URL a tool parameter can reach."
    ),
    "auth-posture": (
        "Put an explicit auth dependency and a rate limiter in front of "
        "every mutating route; never bind `0.0.0.0` with `debug=True`. "
        "Prefer localhost/tailnet binds for anything not deliberately "
        "public."
    ),
    "secret-handling": (
        "Move secrets out of tracked files and source literals into "
        "environment variables or a secret manager; never pass a secret "
        "to `print`/`log.*`. Rotate anything that was ever committed -- "
        "removal from the working tree does not un-leak it."
    ),
    "tool-scope-creep": (
        "Gate every mutating MCP tool behind an explicit permission group "
        "or env-flag opt-in, default OFF. A tool the LLM can call is an "
        "attacker-reachable surface; register write capabilities "
        "separately from read capabilities."
    ),
    "secret-leak-via-tool-response": (
        "Audit what every tool's return value actually sends back to the "
        "calling LLM: never return `os.environ`, whole config/settings "
        "objects, or secret-named fields. Return the minimal data the "
        "tool's purpose requires."
    ),
    "job-overbroad-scope": (
        "Scope every scheduled job's credentials/ACLs to exactly what it "
        "needs (least privilege); split broad admin credentials into "
        "narrow per-job ones."
    ),
    "job-destructive-no-confirm": (
        "Put an explicit confirm-before-destroy gate (or a dry-run "
        "default) in front of destructive calls in scheduled jobs and "
        "wrappers; irreversible actions should default-deny."
    ),
    "job-unverified-success": (
        "Make jobs verify what they actually did before reporting "
        "success: no `|| true`, bare `exit 0`, `continue-on-error`, or "
        "empty `catch {}` around the payload step."
    ),
}

GENERIC_REMEDIATION = (
    "No curated class-level guidance is mapped for this vulnerability "
    "class yet -- follow the finding-specific fix, and treat the flagged "
    "pattern as attacker-reachable until a human review proves otherwise."
)

_REACH_ORDER = ("reachable", "cli-only", "uncalled", "unreachable-by-tools", "unknown")


class ReportInputError(ValueError):
    """Bad scan JSON / annotations input -- reported cleanly, never a traceback."""


# --------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------- #
def load_scan(path: "str | Path", target: "str | None" = None) -> dict:
    """Load one scan-result dict from a scan JSON file.

    Accepts the single-result shape (`mcp-scan <path> --json`), a list of
    results (`--self-audit --json`; select with ``target`` = list index or
    a target-path suffix), or a mapping of name -> result (ecosystem-scan
    raw results; select with ``target`` = key). Findings without a
    ``finding_id`` (older JSONs) get deterministic ids computed by the
    same shared function the scanner emits with.
    """
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ReportInputError(f"cannot read scan JSON {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise ReportInputError(f"{p} is not valid JSON: {e}") from e

    scan = _select_result(data, target, p)
    if not isinstance(scan, dict) or "findings" not in scan:
        raise ReportInputError(
            f"{p} does not look like mcp-scan output (no 'findings' key)")
    _ensure_finding_ids(scan)
    return scan


def _select_result(data, target: "str | None", p: Path) -> dict:
    if isinstance(data, dict) and "findings" in data:
        return data
    if isinstance(data, dict):
        keys = sorted(data)
        if target is not None:
            if target not in data:
                raise ReportInputError(
                    f"--target {target!r} not in {p}; available: {', '.join(keys)}")
            return data[target]
        raise ReportInputError(
            f"{p} holds multiple named scan results; pick one with "
            f"--target. Available: {', '.join(keys)}")
    if isinstance(data, list):
        if target is not None:
            for i, entry in enumerate(data):
                if str(i) == target or str(entry.get("target", "")).endswith(target):
                    return entry
            raise ReportInputError(
                f"--target {target!r} matches no entry in {p} "
                f"(use a list index or a target-path suffix)")
        raise ReportInputError(
            f"{p} holds a list of scan results; pick one with "
            "--target <index or target-path suffix>")
    raise ReportInputError(f"unrecognized scan JSON shape in {p}")


def _ensure_finding_ids(scan: dict) -> None:
    findings = scan.get("findings", [])
    if all("finding_id" in f for f in findings):
        return
    ids = assign_finding_ids(
        [(f.get("vuln_class", ""), f.get("file", ""), f.get("title", ""))
         for f in findings])
    for fid, f in zip(ids, findings):
        f["finding_id"] = fid


def load_annotations(path: "str | Path") -> dict:
    """Load triage.toml -> {finding_id: {verdict, note, reviewed_by}}."""
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as e:
        raise ReportInputError(f"cannot read annotations {p}: {e}") from e
    except tomllib.TOMLDecodeError as e:
        raise ReportInputError(f"{p} is not valid TOML: {e}") from e

    table = data.get("findings")
    if not isinstance(table, dict):
        raise ReportInputError(
            f"{p} has no [findings.<finding_id>] tables -- see the "
            "triage.toml schema in the spec")
    out: dict[str, dict] = {}
    for fid, entry in table.items():
        if not isinstance(entry, dict):
            raise ReportInputError(f"{p}: [findings.{fid}] is not a table")
        verdict = entry.get("verdict")
        if verdict not in VERDICTS:
            raise ReportInputError(
                f"{p}: [findings.{fid}] verdict {verdict!r} is not one of "
                f"{', '.join(VERDICTS)}")
        out[fid] = {
            "verdict": verdict,
            "note": str(entry.get("note", "")),
            "reviewed_by": str(entry.get("reviewed_by", "")),
        }
    return out


# --------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------- #
def _sort_key(f: dict):
    sev_rank = {s: i for i, s in enumerate(_SEVERITIES)}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    return (sev_rank.get(f.get("severity"), len(_SEVERITIES)),
            conf_rank.get(f.get("confidence"), len(conf_rank)),
            f.get("file", ""), f.get("line", 0))


def build_report_model(scan: dict, annotations: dict, *,
                       client: str = "the client",
                       engagement: str = "MCP Server Security Audit",
                       scope: str = "",
                       annotations_name: str = "") -> dict:
    """Join scan JSON + annotations into the render-ready model. Pure --
    everything downstream is derived from the two inputs, so renders are
    byte-stable given fixed inputs."""
    meta = scan.get("scan_meta") or {}
    findings = sorted((dict(f) for f in scan.get("findings", [])), key=_sort_key)

    known_ids = {f["finding_id"] for f in findings}
    unknown = [
        {"finding_id": fid, **entry}
        for fid, entry in sorted(annotations.items()) if fid not in known_ids
    ]

    for f in findings:
        ann = annotations.get(f["finding_id"])
        f["verdict"] = ann["verdict"] if ann else UNREVIEWED
        f["note"] = ann["note"] if ann else ""
        f["reviewed_by"] = ann["reviewed_by"] if ann else ""
        f["remediation_guidance"] = REMEDIATION_GUIDANCE.get(
            f.get("vuln_class", ""), GENERIC_REMEDIATION)

    by_severity = {s: 0 for s in _SEVERITIES}
    by_verdict = {v: 0 for v in (*VERDICTS, UNREVIEWED)}
    severity_verdict = {s: {v: 0 for v in (*VERDICTS, UNREVIEWED)}
                        for s in _SEVERITIES}
    severity_reachability: dict[str, dict[str, int]] = {s: {} for s in _SEVERITIES}
    for f in findings:
        sev = f.get("severity", "P3")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_verdict[f["verdict"]] += 1
        severity_verdict.setdefault(sev, {v: 0 for v in (*VERDICTS, UNREVIEWED)})
        severity_verdict[sev][f["verdict"]] += 1
        reach = f.get("reachability", "unknown")
        severity_reachability.setdefault(sev, {})
        severity_reachability[sev][reach] = severity_reachability[sev].get(reach, 0) + 1

    confirmed = [f for f in findings if f["verdict"] == "confirmed"]
    post_triage_clean = not any(
        f.get("severity") in ("P0", "P1") for f in confirmed)

    # Top risks: confirmed first, then unreviewed -- never a finding a
    # human already dismissed/accepted/mitigated.
    candidates = confirmed + [f for f in findings if f["verdict"] == UNREVIEWED]
    top_risks = candidates[:3]

    fp_groups: dict[str, list[dict]] = {}
    for f in findings:
        if f["verdict"] == "false-positive":
            fp_groups.setdefault(f.get("vuln_class", ""), []).append(f)

    reviewers = sorted({f["reviewed_by"] for f in findings if f["reviewed_by"]})

    return {
        "client": client,
        "engagement": engagement,
        "scope": scope or _short(str(scan.get("target", ""))),
        "target": str(scan.get("target", "")),
        "files_scanned": scan.get("files_scanned", 0),
        "errors": list(scan.get("errors", [])),
        "scan_date": meta.get("scan_date", "") or "(not recorded in scan JSON)",
        "scanner_version": meta.get("scanner_version", "") or "(not recorded in scan JSON)",
        "suite_counts": meta.get("suite_counts"),
        "annotations_name": annotations_name,
        "annotations_applied": sum(
            1 for f in findings if f["verdict"] != UNREVIEWED),
        "reviewers": reviewers,
        "findings": findings,
        "counts": {
            "raw_total": len(findings),
            "by_severity": by_severity,
            "by_verdict": by_verdict,
            "severity_verdict": severity_verdict,
            "severity_reachability": severity_reachability,
        },
        "clean_bill": bool(scan.get("clean_bill", not findings)),
        "post_triage_clean": post_triage_clean,
        "top_risks": top_risks,
        "fp_groups": [
            {"vuln_class": vc, "items": items}
            for vc, items in sorted(fp_groups.items())
        ],
        "unknown_annotations": unknown,
    }


# --------------------------------------------------------------------- #
# Shared prose builders (data-slotted templates -- no free invention)
# --------------------------------------------------------------------- #
def _posture_paragraph(m: dict) -> str:
    c = m["counts"]
    v = c["by_verdict"]
    reviewed = m["annotations_applied"]
    parts = [
        f"The scanner produced {c['raw_total']} raw finding(s) across "
        f"{m['files_scanned']} scanned file(s) in `{_short(m['target'])}`."
    ]
    if reviewed:
        parts.append(
            f"After human triage, {v['confirmed']} are confirmed real, "
            f"{v['false-positive']} were dismissed as false positives, "
            f"{v['accepted-risk']} accepted as risk, {v['mitigated']} "
            f"already mitigated, and {v[UNREVIEWED]} remain unreviewed."
        )
    else:
        parts.append(
            "No triage annotations were supplied: every finding below is "
            "UNREVIEWED. Treat this as the scanner's raw, deliberately "
            "over-flagging output, not a human-verified risk list."
        )
    if m["post_triage_clean"] and reviewed:
        parts.append(
            "No confirmed critical (P0) or high (P1) risk remains after "
            "triage."
        )
    elif not m["post_triage_clean"]:
        sv = c["severity_verdict"]
        parts.append(
            f"{sv['P0']['confirmed'] + sv['P1']['confirmed']} confirmed "
            "critical/high finding(s) require action."
        )
    return " ".join(parts)


def _clean_bill_statement(m: dict) -> str:
    if m["clean_bill"]:
        return (
            f"Clean bill of health for `{_short(m['target'])}`: the scan "
            "found no critical (P0) or high (P1) findings. Per the "
            "methodology section, this means no critical/high patterns "
            "were found by these detectors -- not a guarantee of security."
        )
    c = m["counts"]["by_severity"]
    return (
        f"`{_short(m['target'])}` does not get a clean bill on the raw "
        f"scan: {c['P0']} critical (P0) and {c['P1']} high (P1) "
        "finding(s) before triage. The triage summary below is the honest "
        "read of how many survive human review."
    )


def _misled_line(m: dict) -> str:
    c = m["counts"]
    v = c["by_verdict"]
    if not m["annotations_applied"]:
        return (
            "No triage pass has been applied yet -- the raw count below "
            "is NOT a risk count. This scanner over-flags by design; "
            "expect a substantial share of raw findings to fall to human "
            "review."
        )
    return (
        f"What the raw number would have misled you about: "
        f"{c['raw_total']} raw finding(s) reduce to {v['confirmed']} "
        f"confirmed after human triage -- the raw count alone would have "
        f"overstated the real risk surface by "
        f"{c['raw_total'] - v['confirmed']} finding(s)."
    )


def _suite_counts_phrase(m: dict) -> str:
    sc = m["suite_counts"]
    if not sc:
        return "(not recorded in scan JSON)"
    return (f"{sc.get('total', '?')} tests ({sc.get('passed', '?')} passing, "
            f"{sc.get('skipped', '?')} environment-gated skips)")


_VERDICT_COLUMNS = (*VERDICTS, UNREVIEWED)


# --------------------------------------------------------------------- #
# Markdown renderer
# --------------------------------------------------------------------- #
def render_markdown_report(m: dict) -> str:
    L: list[str] = []
    add = L.append

    add(f"# {m['engagement']} -- {m['client']}")
    add("")

    # 1. Cover / meta ---------------------------------------------------- #
    add("## 1. Engagement & scan metadata")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Client | {_md_cell(m['client'])} |")
    add(f"| Engagement | {_md_cell(m['engagement'])} |")
    add(f"| Scope | {_md_cell(m['scope'])} |")
    add(f"| Target | `{_md_cell(m['target'])}` |")
    add(f"| Scan date | {_md_cell(m['scan_date'])} |")
    add(f"| Scanner version (git) | `{_md_cell(m['scanner_version'])}` |")
    add(f"| Scanner test suite at that version | {_suite_counts_phrase(m)} |")
    ann = m["annotations_name"] or "(none supplied -- all findings unreviewed)"
    add(f"| Triage annotations | {_md_cell(ann)} |")
    if m["reviewers"]:
        add(f"| Reviewed by | {_md_cell(', '.join(m['reviewers']))} |")
    add("")

    # 2. Executive summary ---------------------------------------------- #
    add("## 2. Executive summary")
    add("")
    add(_posture_paragraph(m))
    add("")
    add(_clean_bill_statement(m))
    add("")
    add("**Severity legend:** "
        + "; ".join(f"**{s}** = {d}" for s, d in SEVERITY_LEGEND) + ".")
    add("")
    add("| Severity | " + " | ".join(VERDICT_LABEL[v] for v in _VERDICT_COLUMNS)
        + " | Raw |")
    add("|---|" + "---|" * (len(_VERDICT_COLUMNS) + 1))
    for sev in _SEVERITIES:
        row = m["counts"]["severity_verdict"][sev]
        add(f"| {sev} | " + " | ".join(str(row[v]) for v in _VERDICT_COLUMNS)
            + f" | {m['counts']['by_severity'][sev]} |")
    add("")
    add("Reachability of the raw findings (per severity): "
        + "; ".join(
            f"{sev}: " + (", ".join(
                f"{n} {reach}" for reach, n in sorted(
                    m["counts"]["severity_reachability"][sev].items(),
                    key=lambda kv: _REACH_ORDER.index(kv[0])
                    if kv[0] in _REACH_ORDER else len(_REACH_ORDER)))
                or "none")
            for sev in _SEVERITIES) + ".")
    add("")
    add("**Top-3 risks (confirmed first, then unreviewed):**")
    add("")
    if m["top_risks"]:
        for n, f in enumerate(m["top_risks"], start=1):
            incident = VULN_CLASS_INCIDENT_LANG.get(
                f.get("vuln_class", ""), "a flagged risky pattern")
            add(f"{n}. **[{f['severity']}/{VERDICT_LABEL[f['verdict']]}]** "
                f"`{f['file']}:{f['line']}` -- {incident} "
                f"(`{f['finding_id']}`).")
    else:
        add("_None -- every raw finding was dismissed, accepted, or "
            "mitigated in triage (or the scan was clean)._")
    add("")

    # 3. Triage summary -------------------------------------------------- #
    add("## 3. Triage summary")
    add("")
    add(_misled_line(m))
    add("")
    add("| Verdict | Count |")
    add("|---|---|")
    for v in _VERDICT_COLUMNS:
        add(f"| {VERDICT_LABEL[v]} | {m['counts']['by_verdict'][v]} |")
    add(f"| **Raw total** | {m['counts']['raw_total']} |")
    add("")
    if m["fp_groups"]:
        add("**False-positive classes encountered** (each dismissal carries "
            "the reviewer's reasoning -- this is what separates a triaged "
            "report from a pattern dump):")
        add("")
        for grp in m["fp_groups"]:
            add(f"- `{grp['vuln_class']}`:")
            for f in grp["items"]:
                note = f["note"] or "(no note recorded)"
                add(f"  - `{f['file']}:{f['line']}` (`{f['finding_id']}`) -- "
                    f"{_md_cell(note)}")
        add("")
    if m["unknown_annotations"]:
        add("> [!warning] Stale triage annotations -- action needed")
        add("> The annotations file references finding ids that are NOT in "
            "this scan (the finding may have been fixed, or the file "
            "renamed). They are listed here rather than silently dropped:")
        add(">")
        for w in m["unknown_annotations"]:
            note = w.get("note") or "(no note)"
            add(f"> - `{w['finding_id']}` -- {VERDICT_LABEL[w['verdict']]}: "
                f"{_md_cell(note)}")
        add("")

    # 4. Findings detail -------------------------------------------------- #
    add("## 4. Findings detail")
    add("")
    if not m["findings"]:
        add("_No findings in this scan._")
        add("")
    for f in m["findings"]:
        add(f"### `{f['finding_id']}` -- {_first_sentence(f.get('title', ''))}")
        add("")
        add(f"- **Severity / confidence:** {f['severity']} / {f.get('confidence', 'unknown')}")
        add(f"- **Verdict:** {VERDICT_LABEL[f['verdict']]}"
            + (f" (reviewed by {f['reviewed_by']})" if f["reviewed_by"] else ""))
        if f["note"]:
            add(f"- **Reviewer note:** {_md_cell(f['note'])}")
        add(f"- **Class:** `{f.get('vuln_class', '')}`")
        add(f"- **Location:** `{f['file']}:{f['line']}`")
        add(f"- **Reachability / taint:** {f.get('reachability', 'unknown')} / "
            f"{f.get('taint', 'unknown')}")
        if f.get("reachability_evidence"):
            add(f"- **Reachability evidence:** {_md_cell(f['reachability_evidence'])}")
        add(f"- **What was found:** {_md_cell(f.get('detail', ''))}")
        if f.get("snippet"):
            add(f"- **Evidence:** `{_md_cell(f['snippet'])}`")
        add(f"- **Specific fix:** {_md_cell(f.get('remediation', ''))}")
        add(f"- **Class remediation guidance:** {_md_cell(f['remediation_guidance'])}")
        add("")

    # 5. Methodology ------------------------------------------------------ #
    add("## 5. Methodology & honest capability boundary")
    add("")
    add("Stated plainly so the tool-vs-expert split is contractual, not "
        "verbal:")
    add("")
    for entry in CAPABILITY_BOUNDARY:
        add(f"**{entry['title']}.** {entry['body']}")
        add("")

    # 6. Appendix --------------------------------------------------------- #
    add("## 6. Appendix")
    add("")
    add("### Detector families")
    add("")
    add("| Class | What it checks |")
    add("|---|---|")
    for vc, desc in DETECTOR_CLASS_TABLE:
        add(f"| `{vc}` | {_md_cell(desc)} |")
    add("")
    add("### Scan configuration")
    add("")
    add(f"- Target: `{m['target']}`")
    add(f"- Files scanned: {m['files_scanned']}")
    add(f"- Scanner version: `{m['scanner_version']}`")
    if m["errors"]:
        add("- Scan notes/errors:")
        for e in m["errors"]:
            add(f"  - {_md_cell(str(e))}")
    else:
        add("- Scan notes/errors: none")
    add("")
    add("### Annotation provenance")
    add("")
    if m["annotations_name"]:
        add(f"- Annotations file: `{m['annotations_name']}`")
        add(f"- Annotations applied to findings in this scan: "
            f"{m['annotations_applied']}")
        add(f"- Annotations referencing unknown ids: "
            f"{len(m['unknown_annotations'])}")
        if m["reviewers"]:
            add(f"- Reviewers: {', '.join(m['reviewers'])}")
    else:
        add("- No annotations file was supplied; every verdict above is "
            "Unreviewed.")
    add("")
    return "\n".join(L)


# --------------------------------------------------------------------- #
# HTML renderer (self-contained: inline CSS, zero external URLs)
# --------------------------------------------------------------------- #
_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a;
       margin: 0 auto; max-width: 52rem; padding: 2rem 1.5rem; line-height: 1.55;
       background: #ffffff; }
h1 { font-size: 1.7rem; border-bottom: 3px solid #1a1a1a; padding-bottom: .4rem; }
h2 { font-size: 1.25rem; margin-top: 2.2rem; border-bottom: 1px solid #999;
     padding-bottom: .25rem; }
h3 { font-size: 1.02rem; margin-top: 1.6rem; }
table { border-collapse: collapse; width: 100%; margin: .8rem 0; font-size: .92rem; }
th, td { border: 1px solid #bbb; padding: .35rem .55rem; text-align: left;
         vertical-align: top; }
th { background: #f0efe9; }
code { font-family: Consolas, 'Courier New', monospace; font-size: .88em;
       background: #f4f3ee; padding: .05rem .25rem; }
.warn { border: 2px solid #a33; background: #fbeeee; padding: .7rem 1rem;
        margin: 1rem 0; }
.warn strong { color: #a33; }
.finding { border: 1px solid #ccc; border-left: 5px solid #888;
           padding: .6rem 1rem; margin: .9rem 0; page-break-inside: avoid; }
.finding.sev-P0 { border-left-color: #a31515; }
.finding.sev-P1 { border-left-color: #c96a11; }
.finding.sev-P2 { border-left-color: #a08a00; }
.finding.sev-P3 { border-left-color: #4a7a4a; }
.badge { display: inline-block; font-family: Consolas, monospace;
         font-size: .78rem; border: 1px solid #888; padding: .05rem .4rem;
         margin-right: .3rem; background: #f4f3ee; }
.meta-table td:first-child { width: 15rem; font-weight: bold; }
.boundary p { margin: .5rem 0 1rem 0; }
footer { margin-top: 2.5rem; font-size: .8rem; color: #555;
         border-top: 1px solid #999; padding-top: .5rem; }
@media print {
  body { max-width: none; padding: 0; font-size: 11pt; }
  h2 { page-break-after: avoid; }
  .finding { page-break-inside: avoid; }
}
"""


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def render_html_report(m: dict) -> str:
    H: list[str] = []
    add = H.append
    add("<!DOCTYPE html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>{_e(m['engagement'])} -- {_e(m['client'])}</title>")
    add(f"<style>{_CSS}</style></head><body>")
    add(f"<h1>{_e(m['engagement'])} &mdash; {_e(m['client'])}</h1>")

    # 1. Cover / meta ---------------------------------------------------- #
    add("<h2>1. Engagement &amp; scan metadata</h2>")
    add('<table class="meta-table">')
    rows = [
        ("Client", m["client"]),
        ("Engagement", m["engagement"]),
        ("Scope", m["scope"]),
        ("Target", m["target"]),
        ("Scan date", m["scan_date"]),
        ("Scanner version (git)", m["scanner_version"]),
        ("Scanner test suite at that version", _suite_counts_phrase(m)),
        ("Triage annotations",
         m["annotations_name"] or "(none supplied -- all findings unreviewed)"),
    ]
    if m["reviewers"]:
        rows.append(("Reviewed by", ", ".join(m["reviewers"])))
    for k, v in rows:
        add(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>")
    add("</table>")

    # 2. Executive summary ---------------------------------------------- #
    add("<h2>2. Executive summary</h2>")
    add(f"<p>{_e(_posture_paragraph(m))}</p>")
    add(f"<p>{_e(_clean_bill_statement(m))}</p>")
    add("<p><strong>Severity legend:</strong> "
        + "; ".join(f"<strong>{_e(s)}</strong> = {_e(d)}"
                    for s, d in SEVERITY_LEGEND) + ".</p>")
    add("<table><tr><th>Severity</th>"
        + "".join(f"<th>{_e(VERDICT_LABEL[v])}</th>" for v in _VERDICT_COLUMNS)
        + "<th>Raw</th></tr>")
    for sev in _SEVERITIES:
        row = m["counts"]["severity_verdict"][sev]
        add(f"<tr><td>{sev}</td>"
            + "".join(f"<td>{row[v]}</td>" for v in _VERDICT_COLUMNS)
            + f"<td>{m['counts']['by_severity'][sev]}</td></tr>")
    add("</table>")
    add("<p><strong>Top-3 risks (confirmed first, then unreviewed):</strong></p>")
    if m["top_risks"]:
        add("<ol>")
        for f in m["top_risks"]:
            incident = VULN_CLASS_INCIDENT_LANG.get(
                f.get("vuln_class", ""), "a flagged risky pattern")
            add(f"<li><span class='badge'>{_e(f['severity'])}</span>"
                f"<span class='badge'>{_e(VERDICT_LABEL[f['verdict']])}</span> "
                f"<code>{_e(f['file'])}:{_e(f['line'])}</code> &mdash; "
                f"{_e(incident)} (<code>{_e(f['finding_id'])}</code>).</li>")
        add("</ol>")
    else:
        add("<p><em>None &mdash; every raw finding was dismissed, accepted, "
            "or mitigated in triage (or the scan was clean).</em></p>")

    # 3. Triage summary -------------------------------------------------- #
    add("<h2>3. Triage summary</h2>")
    add(f"<p>{_e(_misled_line(m))}</p>")
    add("<table><tr><th>Verdict</th><th>Count</th></tr>")
    for v in _VERDICT_COLUMNS:
        add(f"<tr><td>{_e(VERDICT_LABEL[v])}</td>"
            f"<td>{m['counts']['by_verdict'][v]}</td></tr>")
    add(f"<tr><th>Raw total</th><th>{m['counts']['raw_total']}</th></tr>")
    add("</table>")
    if m["fp_groups"]:
        add("<p><strong>False-positive classes encountered</strong> (each "
            "dismissal carries the reviewer's reasoning):</p><ul>")
        for grp in m["fp_groups"]:
            add(f"<li><code>{_e(grp['vuln_class'])}</code><ul>")
            for f in grp["items"]:
                note = f["note"] or "(no note recorded)"
                add(f"<li><code>{_e(f['file'])}:{_e(f['line'])}</code> "
                    f"(<code>{_e(f['finding_id'])}</code>) &mdash; "
                    f"{_e(note)}</li>")
            add("</ul></li>")
        add("</ul>")
    if m["unknown_annotations"]:
        add('<div class="warn"><strong>Stale triage annotations &mdash; '
            "action needed.</strong> The annotations file references "
            "finding ids that are NOT in this scan (the finding may have "
            "been fixed, or the file renamed). Listed here rather than "
            "silently dropped:<ul>")
        for w in m["unknown_annotations"]:
            note = w.get("note") or "(no note)"
            add(f"<li><code>{_e(w['finding_id'])}</code> &mdash; "
                f"{_e(VERDICT_LABEL[w['verdict']])}: {_e(note)}</li>")
        add("</ul></div>")

    # 4. Findings detail -------------------------------------------------- #
    add("<h2>4. Findings detail</h2>")
    if not m["findings"]:
        add("<p><em>No findings in this scan.</em></p>")
    for f in m["findings"]:
        add(f"<div class='finding sev-{_e(f['severity'])}'>")
        add(f"<h3><code>{_e(f['finding_id'])}</code> &mdash; "
            f"{_e(_first_sentence(f.get('title', '')))}</h3>")
        add("<p>"
            f"<span class='badge'>{_e(f['severity'])}</span>"
            f"<span class='badge'>confidence: {_e(f.get('confidence', 'unknown'))}</span>"
            f"<span class='badge'>verdict: {_e(VERDICT_LABEL[f['verdict']])}</span>"
            f"<span class='badge'>reachability: {_e(f.get('reachability', 'unknown'))}</span>"
            f"<span class='badge'>taint: {_e(f.get('taint', 'unknown'))}</span>"
            f"<span class='badge'>class: {_e(f.get('vuln_class', ''))}</span>"
            "</p>")
        add("<table>")
        add(f"<tr><td>Location</td><td><code>{_e(f['file'])}:{_e(f['line'])}"
            "</code></td></tr>")
        if f["reviewed_by"]:
            add(f"<tr><td>Reviewed by</td><td>{_e(f['reviewed_by'])}</td></tr>")
        if f["note"]:
            add(f"<tr><td>Reviewer note</td><td>{_e(f['note'])}</td></tr>")
        add(f"<tr><td>What was found</td><td>{_e(f.get('detail', ''))}</td></tr>")
        if f.get("snippet"):
            add(f"<tr><td>Evidence</td><td><code>{_e(f['snippet'])}</code></td></tr>")
        if f.get("reachability_evidence"):
            add(f"<tr><td>Reachability evidence</td>"
                f"<td>{_e(f['reachability_evidence'])}</td></tr>")
        add(f"<tr><td>Specific fix</td><td>{_e(f.get('remediation', ''))}</td></tr>")
        add(f"<tr><td>Class remediation guidance</td>"
            f"<td>{_e(f['remediation_guidance'])}</td></tr>")
        add("</table></div>")

    # 5. Methodology ------------------------------------------------------ #
    add("<h2>5. Methodology &amp; honest capability boundary</h2>")
    add('<div class="boundary">')
    add("<p>Stated plainly so the tool-vs-expert split is contractual, "
        "not verbal:</p>")
    for entry in CAPABILITY_BOUNDARY:
        add(f"<p><strong>{_e(entry['title'])}.</strong> "
            f"{_e(entry['body'])}</p>")
    add("</div>")

    # 6. Appendix --------------------------------------------------------- #
    add("<h2>6. Appendix</h2>")
    add("<h3>Detector families</h3>")
    add("<table><tr><th>Class</th><th>What it checks</th></tr>")
    for vc, desc in DETECTOR_CLASS_TABLE:
        add(f"<tr><td><code>{_e(vc)}</code></td><td>{_e(desc)}</td></tr>")
    add("</table>")
    add("<h3>Scan configuration</h3><ul>")
    add(f"<li>Target: <code>{_e(m['target'])}</code></li>")
    add(f"<li>Files scanned: {m['files_scanned']}</li>")
    add(f"<li>Scanner version: <code>{_e(m['scanner_version'])}</code></li>")
    if m["errors"]:
        add("<li>Scan notes/errors:<ul>")
        for e in m["errors"]:
            add(f"<li>{_e(e)}</li>")
        add("</ul></li>")
    else:
        add("<li>Scan notes/errors: none</li>")
    add("</ul>")
    add("<h3>Annotation provenance</h3><ul>")
    if m["annotations_name"]:
        add(f"<li>Annotations file: <code>{_e(m['annotations_name'])}</code></li>")
        add(f"<li>Annotations applied to findings in this scan: "
            f"{m['annotations_applied']}</li>")
        add(f"<li>Annotations referencing unknown ids: "
            f"{len(m['unknown_annotations'])}</li>")
        if m["reviewers"]:
            add(f"<li>Reviewers: {_e(', '.join(m['reviewers']))}</li>")
    else:
        add("<li>No annotations file was supplied; every verdict above is "
            "Unreviewed.</li>")
    add("</ul>")
    add(f"<footer>Generated by mcp-scan report, scanner version "
        f"<code>{_e(m['scanner_version'])}</code>, from scan data of "
        f"{_e(m['scan_date'])}. Print this page to PDF for a client "
        "deliverable &mdash; the file is fully self-contained.</footer>")
    add("</body></html>")
    return "\n".join(H)


# --------------------------------------------------------------------- #
# CLI entry (dispatched from cli.main on `mcp-scan report ...`)
# --------------------------------------------------------------------- #
def report_main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-scan report",
        description="Render a client-grade report from an existing scan "
                    "JSON (never re-runs the scan) plus an optional "
                    "triage.toml annotations file.",
    )
    parser.add_argument("scan_json", help="path to mcp-scan --json output")
    parser.add_argument("--annotations", help="path to triage.toml")
    parser.add_argument("--client", default="the client")
    parser.add_argument("--engagement", default="MCP Server Security Audit")
    parser.add_argument("--scope", default="")
    parser.add_argument("--out", help="write self-contained HTML here")
    parser.add_argument("--md", help="write Markdown here")
    parser.add_argument("--target", default=None,
                        help="which result to report when the JSON holds "
                             "multiple (mapping key, list index, or "
                             "target-path suffix)")
    args = parser.parse_args(argv)

    try:
        scan = load_scan(args.scan_json, target=args.target)
        annotations = load_annotations(args.annotations) if args.annotations else {}
    except ReportInputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    model = build_report_model(
        scan, annotations,
        client=args.client, engagement=args.engagement, scope=args.scope,
        annotations_name=Path(args.annotations).name if args.annotations else "",
    )
    for w in model["unknown_annotations"]:
        print(f"warning: annotation for unknown finding_id {w['finding_id']} "
              "(kept in the report's stale-triage section)", file=sys.stderr)

    wrote_any = False
    if args.out:
        Path(args.out).write_text(render_html_report(model),
                                  encoding="utf-8", newline="\n")
        print(f"wrote {args.out}")
        wrote_any = True
    if args.md:
        Path(args.md).write_text(render_markdown_report(model),
                                 encoding="utf-8", newline="\n")
        print(f"wrote {args.md}")
        wrote_any = True
    if not wrote_any:
        print(render_markdown_report(model))
    return 0
