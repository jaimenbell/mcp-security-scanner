"""Ecosystem-scan v2 -- a repeatable, rails-safe batch scanner.

Turns the hand-done ecosystem scan (clone N public MCP-server repos, run the
scanner over each, triage, write an anonymized aggregate + private disclosure
notes) into a single tool. It is PRESENTATION/ORCHESTRATION only -- it calls
the existing ``scan_repo`` and ``report_generator`` unchanged and contains
ZERO detector logic.

Hard disclosure rails, baked in (see ``tests/test_ecosystem_scan.py``):

* **R1 -- no third-party name in a tracked file, ever.** Every artifact this
  tool writes (aggregate report, raw results, per-repo reports, disclosure
  notes) goes to a gitignored local dir. The default out/scratch dirs and the
  real config file are all in ``.gitignore``; the shipped example config
  carries only placeholder/local paths.
* **R2 -- anything above LOW confidence is a DISCLOSURE CANDIDATE**, written
  PRIVATE / operator-review-required, following the target repo's OWN
  ``SECURITY`` policy (read from the clone, never invented). The tool never
  contacts anyone, files anything, or names a target publicly -- it stages;
  the operator discloses.
* **R3 -- read-only toward third-party repos.** Clone (to scratch) + scan.
  Never a write back into a target.
* **R4 -- no network in tests.** The clone function is injected everywhere;
  the real ``git clone`` path is only reached for URL targets in a real run.

The aggregate report is the one artifact deliberately built to be
*shareable* -- it is anonymized (counts, distributions, patterns; no target
names) -- but it is still written only to the gitignored dir; promoting it is
an operator decision, exactly like today's ``staged/`` artifacts.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .scanner import scan_repo

# Default local, GITIGNORED locations (see .gitignore). Bare names so the
# rail test can assert `git check-ignore` on each.
DEFAULT_OUT_DIRNAME = "ecoscan-artifacts"
DEFAULT_SCRATCH_DIRNAME = "ecoscan-scratch"
DEFAULT_CONFIG_NAME = "ecoscan-targets.json"

# A finding is a disclosure candidate when its confidence is ABOVE low.
_ABOVE_LOW = ("medium", "high")
_SEVERITIES = ("P0", "P1", "P2", "P3")
_CONFIDENCES = ("high", "medium", "low")


class EcosystemScanError(Exception):
    """Bad config / input -- reported cleanly, never a traceback."""


@lru_cache(maxsize=1)
def repo_root() -> Path:
    """The scanner checkout root (this file's grandparent)."""
    return Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ #
# Targets / config
# ------------------------------------------------------------------ #
@dataclass(frozen=True)
class Target:
    name: str          # anonymization/display key -- NEVER written to a
                       # tracked file (only into gitignored artifacts)
    location: str      # local filesystem path OR a git URL
    is_url: bool


def _looks_like_url(location: str) -> bool:
    loc = location.strip()
    return (
        loc.startswith(("http://", "https://", "git://", "ssh://"))
        or (loc.startswith("git@") and ":" in loc)
    )


def load_targets(config_path: "str | Path") -> list[Target]:
    """Load the target list from a JSON config:

    ``{"targets": [{"name": "...", "location": "<path or git URL>"}, ...]}``

    ``is_url`` is auto-detected from the location shape.
    """
    p = Path(config_path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except OSError as e:
        raise EcosystemScanError(f"cannot read config {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise EcosystemScanError(f"{p} is not valid JSON: {e}") from e

    rows = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows:
        raise EcosystemScanError(
            f"{p} has no non-empty 'targets' list -- see "
            f"{DEFAULT_CONFIG_NAME}.example")
    targets: list[Target] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or "name" not in row or "location" not in row:
            raise EcosystemScanError(
                f"{p}: targets[{i}] needs both 'name' and 'location'")
        loc = str(row["location"])
        targets.append(Target(name=str(row["name"]), location=loc,
                              is_url=_looks_like_url(loc)))
    return targets


# ------------------------------------------------------------------ #
# Clone / resolve (R3 read-only, R4 injectable)
# ------------------------------------------------------------------ #
def shallow_clone(url: str, dest: "str | Path", *, run=subprocess.run) -> Path:
    """Shallow (`--depth 1`) clone ``url`` into ``dest``. ``run`` is
    injectable so tests never spawn git or touch the network."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", url, str(dest)]
    proc = run(cmd, capture_output=True, text=True)
    if getattr(proc, "returncode", 0) != 0:
        raise EcosystemScanError(
            f"clone failed for {url}: {getattr(proc, 'stderr', '')[:400]}")
    return dest


def resolve_target(target: Target, scratch_dir: "str | Path", *,
                   clone=shallow_clone) -> Path:
    """Return the on-disk path to scan for ``target``.

    Local paths are returned as-is and NEVER cloned (a fully-local run makes
    zero network calls). URL targets are cloned into ``scratch_dir/<name>``
    via the (injectable) ``clone`` function -- read-only toward the source.
    """
    if not target.is_url:
        path = Path(target.location)
        if not path.exists():
            raise EcosystemScanError(
                f"local target {target.name!r} path does not exist: {path}")
        return path
    dest = Path(scratch_dir) / _safe_slug(target.name)
    return Path(clone(target.location, dest))


def _safe_slug(name: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)


# ------------------------------------------------------------------ #
# Scan
# ------------------------------------------------------------------ #
def scan_targets(targets: list[Target], scratch_dir: "str | Path", *,
                 clone=shallow_clone, scan=scan_repo) -> dict:
    """Resolve + scan every target. Returns ``{name: scan_dict}`` (the
    ``ScanResult.to_dict()`` shape the report generator already consumes)."""
    Path(scratch_dir).mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}
    for t in targets:
        path = resolve_target(t, scratch_dir, clone=clone)
        results[t.name] = scan(str(path)).to_dict()
    return results


# ------------------------------------------------------------------ #
# Disclosure candidates (R2)
# ------------------------------------------------------------------ #
def disclosure_candidates(scan_dict: dict) -> list[dict]:
    """Findings ABOVE low confidence -- each is operator-review material,
    never a publishable fact."""
    return [f for f in scan_dict.get("findings", [])
            if f.get("confidence") in _ABOVE_LOW]


def read_security_policy(repo_path: "str | Path") -> "str | None":
    """Read the target repo's own SECURITY policy text, or ``None`` if the
    repo has none. The tool NEVER invents a channel."""
    root = Path(repo_path)
    for rel in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
                "SECURITY", ".github/SECURITY", "SECURITY.txt"):
        p = root / rel
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
    return None


# ------------------------------------------------------------------ #
# Aggregate roll-up
# ------------------------------------------------------------------ #
def build_aggregate(results: dict) -> dict:
    """Roll up counts across all targets -- severity x confidence x class,
    plus the raw-vs-triaged framing. Contains ZERO target names."""
    by_severity = {s: 0 for s in _SEVERITIES}
    by_confidence = {c: 0 for c in _CONFIDENCES}
    by_reachability: dict[str, int] = {}
    by_class: dict[str, int] = {}
    raw_total = 0
    clean_bill_count = 0
    repos_with_findings = 0
    repos_with_candidates = 0
    candidate_count = 0

    for scan in results.values():
        findings = scan.get("findings", [])
        raw_total += len(findings)
        if scan.get("clean_bill"):
            clean_bill_count += 1
        if findings:
            repos_with_findings += 1
        cands = disclosure_candidates(scan)
        if cands:
            repos_with_candidates += 1
            candidate_count += len(cands)
        for f in findings:
            by_severity[f.get("severity", "P3")] = \
                by_severity.get(f.get("severity", "P3"), 0) + 1
            by_confidence[f.get("confidence", "low")] = \
                by_confidence.get(f.get("confidence", "low"), 0) + 1
            reach = f.get("reachability", "unknown")
            by_reachability[reach] = by_reachability.get(reach, 0) + 1
            vc = f.get("vuln_class", "")
            by_class[vc] = by_class.get(vc, 0) + 1

    raw_p0_p1 = by_severity.get("P0", 0) + by_severity.get("P1", 0)
    # sort class distribution high->low for the report table
    by_class = dict(sorted(by_class.items(), key=lambda kv: (-kv[1], kv[0])))
    return {
        "repos_scanned": len(results),
        "repos_with_findings": repos_with_findings,
        "clean_bill_count": clean_bill_count,
        "raw_total": raw_total,
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "by_reachability": by_reachability,
        "by_class": by_class,
        "raw_p0_p1": raw_p0_p1,
        "disclosure_candidate_count": candidate_count,
        "repos_with_disclosure_candidates": repos_with_candidates,
    }


def render_aggregate_markdown(agg: dict) -> str:
    """Anonymized aggregate report -- counts/distributions/patterns only,
    NO target names (safe to promote to a public artifact by operator
    decision). Mirrors the hand-done staged/ aggregate shape."""
    L: list[str] = []
    L.append("---")
    L.append("title: MCP Ecosystem Security Posture -- Aggregate Scan")
    L.append("type: aggregate-findings-report")
    L.append("status: draft (anonymized -- no repo named)")
    L.append("---")
    L.append("")
    L.append("# MCP Server Ecosystem -- Aggregate Security Posture")
    L.append("")
    L.append("> [!info] What this is")
    L.append("> Static MCP-server scanner run across a set of public MCP "
             "server repositories, aggregated. Counts, distributions, and "
             "anonymized patterns only -- no finding is tied to a named "
             "repository. Findings above LOW confidence were staged as "
             "PRIVATE disclosure candidates for operator review, not "
             "included here.")
    L.append("")
    L.append("## Results -- aggregate")
    L.append("")
    L.append("| Metric | Value |")
    L.append("|---|---|")
    L.append(f"| Repos scanned | {agg['repos_scanned']} |")
    L.append(f"| Repos with >=1 finding (any severity) | "
             f"{agg['repos_with_findings']} / {agg['repos_scanned']} |")
    L.append(f"| Repos with a clean bill (no P0/P1) | "
             f"{agg['clean_bill_count']} / {agg['repos_scanned']} |")
    L.append(f"| Total raw findings (all severities) | {agg['raw_total']} |")
    sev = agg["by_severity"]
    L.append(f"| Raw severity split | P0: {sev.get('P0', 0)} - "
             f"P1: {sev.get('P1', 0)} - P2: {sev.get('P2', 0)} - "
             f"P3: {sev.get('P3', 0)} |")
    conf = agg["by_confidence"]
    L.append(f"| Confidence split | high: {conf.get('high', 0)} - "
             f"medium: {conf.get('medium', 0)} - low: {conf.get('low', 0)} |")
    reach = agg["by_reachability"]
    reach_str = " - ".join(f"{k}: {v}" for k, v in sorted(reach.items())) or "n/a"
    L.append(f"| Reachability split | {reach_str} |")
    L.append("")
    L.append("## Raw-vs-triaged framing")
    L.append("")
    L.append(f"The scanner emitted **{agg['raw_p0_p1']} raw P0/P1 findings** "
             f"across {agg['repos_scanned']} repos and "
             f"**{agg['disclosure_candidate_count']} findings above LOW "
             f"confidence** (across "
             f"{agg['repos_with_disclosure_candidates']} repos) as disclosure "
             f"candidates. Raw counts are a review queue, not a verdict -- an "
             f"'over-flag, never silently drop' static tool is supposed to "
             f"produce one. Each candidate was staged PRIVATE for a human "
             f"pass before any conclusion; only what survives that pass is "
             f"reportable. That honest gap between raw and reviewed is the "
             f"credibility point, not a weakness.")
    L.append("")
    L.append("## Detector-class distribution (raw, all repos, all severities)")
    L.append("")
    L.append("| Detector class | Findings | Share |")
    L.append("|---|---|---|")
    total = max(agg["raw_total"], 1)
    for vc, n in agg["by_class"].items():
        share = round(100 * n / total)
        L.append(f"| {vc or '(unclassified)'} | {n} | {share}% |")
    L.append("")
    L.append("## Honest scanner limits")
    L.append("")
    L.append("- Static only -- no execution, no dynamic analysis; a clean "
             "bill means no critical/high *static* pattern, not runtime "
             "safety.")
    L.append("- Confidence/reachability grade findings; they never silently "
             "drop one.")
    L.append("- Anything above LOW confidence on a third-party repo is a "
             "disclosure CANDIDATE (operator-reviewed), never a public claim.")
    return "\n".join(L) + "\n"


def render_disclosure_note(name: str, scan_dict: dict,
                           security_policy: "str | None") -> str:
    """PRIVATE, operator-review-required disclosure note for one target.

    Lists the target's above-LOW findings and surfaces the target's OWN
    SECURITY channel (or, when absent, tells the operator to locate it -- the
    tool never invents one). Written only to the gitignored artifacts dir.
    """
    cands = disclosure_candidates(scan_dict)
    L: list[str] = []
    L.append("---")
    L.append(f"title: PRIVATE -- disclosure candidates: {name}")
    L.append("type: disclosure-draft")
    L.append("status: staged-not-sent")
    L.append("classification: private-operator-only")
    L.append("---")
    L.append("")
    L.append("> [!warning] PRIVATE -- Not sent. Operator review required.")
    L.append("> This note names a specific repo and its findings. It is a "
             "gitignored local artifact, excluded from any public output. Do "
             "NOT post, email, or file anything from this note without the "
             "operator's explicit go-ahead. The tool stages only -- it never "
             "contacts anyone or names a target publicly.")
    L.append("")
    L.append(f"## Target: {name}")
    L.append("")
    L.append(f"- Scanned path: `{scan_dict.get('target', '')}`")
    L.append(f"- Above-LOW-confidence findings (disclosure candidates): "
             f"{len(cands)}")
    L.append("")
    L.append("## Disclosure candidates (operator to verify in source)")
    L.append("")
    if cands:
        L.append("| Severity | Confidence | Class | File:line | Reachability |")
        L.append("|---|---|---|---|---|")
        for f in cands:
            L.append(f"| {f.get('severity', '')} | {f.get('confidence', '')} "
                     f"| {f.get('vuln_class', '')} | "
                     f"`{f.get('file', '')}:{f.get('line', '')}` | "
                     f"{f.get('reachability', 'unknown')} |")
    else:
        L.append("_(none above LOW confidence)_")
    L.append("")
    L.append("## Responsible-disclosure channel")
    L.append("")
    if security_policy:
        L.append("The target repo's OWN SECURITY policy (read verbatim from "
                 "the clone -- follow this, it is authoritative over any "
                 "generic guess):")
        L.append("")
        L.append("```")
        L.append(security_policy.strip())
        L.append("```")
    else:
        L.append("No SECURITY policy (SECURITY.md / .github/SECURITY.md / "
                 "SECURITY) was found in the target repo. The tool does NOT "
                 "invent a channel -- the operator must locate the project's "
                 "responsible-disclosure contact (repo docs, maintainer "
                 "profile, or a public security.txt) before any outreach.")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------ #
# Per-repo report (reuses report_generator unchanged)
# ------------------------------------------------------------------ #
def _write_per_repo_report(name: str, scan_dict: dict, out_dir: Path) -> Path:
    from .report_generator import build_report_model, render_markdown_report
    model = build_report_model(
        scan_dict, {},
        client="(private -- operator only)",
        engagement="MCP Ecosystem Scan (third-party, private)",
        scope=name,
    )
    md = render_markdown_report(model)
    path = out_dir / f"report-{_safe_slug(name)}.md"
    path.write_text(md, encoding="utf-8", newline="\n")
    return path


# ------------------------------------------------------------------ #
# Orchestrate
# ------------------------------------------------------------------ #
def run_ecosystem_scan(config_path: "str | Path", *,
                       out_dir: "str | Path | None" = None,
                       scratch_dir: "str | Path | None" = None,
                       clone=shallow_clone, scan=scan_repo) -> dict:
    """End-to-end: load targets -> resolve/scan each -> write raw results,
    per-repo reports, an anonymized aggregate, and PRIVATE disclosure notes
    to the (gitignored) out dir. Returns a summary dict.

    Every artifact goes to ``out_dir`` (default the gitignored
    ``ecoscan-artifacts/``); the aggregate is the only anonymized one.
    """
    out_dir = Path(out_dir) if out_dir is not None \
        else repo_root() / DEFAULT_OUT_DIRNAME
    scratch_dir = Path(scratch_dir) if scratch_dir is not None \
        else repo_root() / DEFAULT_SCRATCH_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch_dir.mkdir(parents=True, exist_ok=True)

    targets = load_targets(config_path)

    results: dict[str, dict] = {}
    resolved_paths: dict[str, Path] = {}
    for t in targets:
        path = resolve_target(t, scratch_dir, clone=clone)
        resolved_paths[t.name] = path
        results[t.name] = scan(str(path)).to_dict()

    # Raw results (PRIVATE -- names + paths). Gitignored dir only.
    (out_dir / "raw-results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8", newline="\n")

    # Per-repo reports (PRIVATE).
    for name, scan_dict in results.items():
        _write_per_repo_report(name, scan_dict, out_dir)

    # Aggregate (anonymized) -- still written private; operator promotes.
    agg = build_aggregate(results)
    (out_dir / "aggregate-report.md").write_text(
        render_aggregate_markdown(agg), encoding="utf-8", newline="\n")

    # PRIVATE disclosure notes for any target with above-LOW findings.
    disclosure_notes = 0
    for name, scan_dict in results.items():
        if not disclosure_candidates(scan_dict):
            continue
        policy = read_security_policy(resolved_paths[name])
        note = render_disclosure_note(name, scan_dict, policy)
        (out_dir / f"disclosure-{_safe_slug(name)}.md").write_text(
            note, encoding="utf-8", newline="\n")
        disclosure_notes += 1

    return {
        "out_dir": str(out_dir),
        "repos_scanned": len(results),
        "per_repo_reports": len(results),
        "disclosure_notes": disclosure_notes,
        "aggregate": agg,
    }


# ------------------------------------------------------------------ #
# CLI (`mcp-scan ecosystem-scan ...`)
# ------------------------------------------------------------------ #
def ecosystem_main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-scan ecosystem-scan",
        description="Batch-scan a list of MCP-server repos and stage an "
                    "anonymized aggregate + PRIVATE per-repo disclosure "
                    "notes to a gitignored local dir. Presentation only -- "
                    "no detector logic; read-only toward targets; the tool "
                    "never contacts anyone or names a target publicly.",
    )
    parser.add_argument(
        "--config", default=str(repo_root() / DEFAULT_CONFIG_NAME),
        help=f"targets JSON (default: {DEFAULT_CONFIG_NAME}, gitignored)")
    parser.add_argument(
        "--out", default=None,
        help=f"artifacts dir (default: {DEFAULT_OUT_DIRNAME}/, gitignored)")
    parser.add_argument(
        "--scratch", default=None,
        help=f"clone scratch dir (default: {DEFAULT_SCRATCH_DIRNAME}/, "
             "gitignored)")
    args = parser.parse_args(argv)

    try:
        summary = run_ecosystem_scan(
            args.config, out_dir=args.out, scratch_dir=args.scratch)
    except EcosystemScanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    agg = summary["aggregate"]
    print(f"scanned {summary['repos_scanned']} repo(s) -> {summary['out_dir']}")
    print(f"  raw findings: {agg['raw_total']} "
          f"(P0/P1: {agg['raw_p0_p1']})")
    print(f"  disclosure candidates (above LOW): "
          f"{agg['disclosure_candidate_count']} in "
          f"{agg['repos_with_disclosure_candidates']} repo(s)")
    print(f"  per-repo reports: {summary['per_repo_reports']}, "
          f"PRIVATE disclosure notes: {summary['disclosure_notes']}")
    print("  aggregate-report.md is anonymized; raw-results.json + "
          "disclosure-*.md are PRIVATE (operator review before any outreach).")
    return 0
