"""Core data model for the MCP security scanner.

A scan produces a flat list of ``Finding`` objects. Every finding carries a
severity, a confidence, and a machine-readable ``vuln_class`` so downstream
reporting (client-facing markdown, JSON, CI gates) can be built without
re-parsing prose.

Honesty note: ``confidence`` is a first-class field because this is a *static*
analyzer. It flags surfaces and patterns; it does not prove exploitability. A
``low``-confidence finding means "a human should look", not "you are owned".
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    """Severity tiers, mirroring the fleet audit's P0-P3 legend."""

    P0 = "P0"  # exploitable now, no preconditions
    P1 = "P1"  # exploitable with attacker-reachable but currently-unmet conditions
    P2 = "P2"  # defense-in-depth gap / conditional
    P3 = "P3"  # hardening nit

    @property
    def rank(self) -> int:
        return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}[self.value]

    @property
    def label(self) -> str:
        return {
            "P0": "Critical",
            "P1": "High",
            "P2": "Medium",
            "P3": "Low",
        }[self.value]


class Confidence(str, Enum):
    """How sure the static pass is that this is real and not a false positive."""

    HIGH = "high"      # concrete sink on a concrete untrusted input
    MEDIUM = "medium"  # risky pattern present, reachability not proven statically
    LOW = "low"        # heuristic / worth-a-look, easily a false positive


class Reachability(str, Enum):
    """Whether a finding sits on code reachable from a registered MCP tool.

    Computed by a post-detector pass (``reachability.py``) using a same-file
    AST call-graph plus best-effort cross-file import following. It never
    drops a finding — it only *labels* it and nudges confidence up or down, in
    keeping with the scanner's deliberate over-flag philosophy.

    CLI_ONLY and UNCALLED (added 2026-07-22, dogfood finding on rag-mcp's
    ``lock.py:144``) refine what used to be lumped into UNREACHABLE for the
    decidable Python-AST case: a finding not reachable from any tool root
    either (a) has a real, statically-found caller elsewhere in the repo —
    CLI_ONLY, since that caller is by construction NOT tool-descended (the
    forward tool walk already failed to reach it) and is typically an argv/
    CLI-main entrypoint or a test file — or (b) has no caller anywhere —
    UNCALLED, genuinely dead code. Both grades are withheld (falling back to
    UNKNOWN) whenever the repo contains any statically-unresolvable call site
    (getattr/locals/globals-style dynamic dispatch) that could plausibly
    reach the finding by a path this scanner cannot see — soundness over
    decidability. UNREACHABLE is kept in the enum for schema stability (JSON
    consumers, the client-report label table) but is no longer emitted by the
    Python-AST decidable branch — CLI_ONLY/UNCALLED/UNKNOWN now cover it.
    """

    REACHABLE = "reachable"                # inside a registered tool handler,
                                           # or a function transitively called
                                           # from one
    CLI_ONLY = "cli-only"                  # has a real caller, but every found
                                           # caller traces to a non-tool
                                           # entrypoint (argv/CLI-main, a test
                                           # file, an admin script) — never a
                                           # registered MCP tool
    UNCALLED = "uncalled"                  # no caller found anywhere in the
                                           # repo (dead code) — stronger than
                                           # UNKNOWN, only asserted when no
                                           # dynamic-dispatch escape hatch
                                           # exists that could hide a caller
    UNREACHABLE = "unreachable-by-tools"   # legacy/reserved: no call path
                                           # from any registered tool reaches
                                           # this code. No longer emitted by
                                           # the current grading logic (see
                                           # CLI_ONLY/UNCALLED above); kept
                                           # for schema/JSON-consumer stability
    UNKNOWN = "unknown"                    # parse/scope limits, no tools
                                           # registered, non-Python surface,
                                           # or dynamic dispatch present that
                                           # makes CLI_ONLY/UNCALLED unsound


class Taint(str, Enum):
    """Whether TOOL-PARAMETER data actually flows into a dangerous sink.

    Computed by a post-detector pass (``taint.py``) that seeds every registered
    tool handler's parameters as taint sources and propagates them through
    assignments, f-strings/concat/format, containers, and same-repo function
    calls (same-file transitively, up to two import hops cross-file) into the
    param-injection detector's dangerous sinks. Like the reachability grade it
    only *labels* a finding and nudges confidence up (TAINTED) or down
    (UNTAINTED) -- it NEVER drops a finding (the over-flag philosophy stands).
    """

    TAINTED = "tainted"        # a tool parameter's value provably reaches the
                               # dangerous argument of this sink
    UNTAINTED = "untainted"    # the sink is in tool-reachable code we analyzed,
                               # but no tool parameter reaches its dangerous arg
                               # (constant / other source) -- lowered, not dropped
    UNKNOWN = "unknown"        # not a dataflow-shaped finding, module-level /
                               # unreachable code, no tools, or non-Python surface


@dataclass(frozen=True)
class Finding:
    """A single detected issue at a source location."""

    vuln_class: str          # stable machine id, e.g. "codegen-injection"
    title: str               # short human title
    severity: Severity
    confidence: Confidence
    file: str                # repo-relative path (posix separators)
    line: int                # 1-based; 0 == whole-file / not line-specific
    detail: str              # what was found
    remediation: str         # what to do about it
    snippet: str = ""        # optional offending source line, trimmed
    # Set by the post-detector reachability pass; UNKNOWN until then, so every
    # existing detector constructor stays valid without change.
    reachability: Reachability = Reachability.UNKNOWN
    # Caller-chain evidence for CLI_ONLY/UNCALLED grades (e.g.
    # "called from _cmd_ingest (cli.py:29); no further caller found -- likely
    # an argv/CLI entrypoint"). Empty for every other grade/every existing
    # constructor, so no change is required at any other call site.
    reachability_evidence: str = ""
    # Set by the post-detector taint pass; UNKNOWN until then (and for every
    # non-dataflow-shaped finding), so every existing constructor stays valid.
    taint: Taint = Taint.UNKNOWN

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["reachability"] = self.reachability.value
        d["taint"] = self.taint.value
        return d


@dataclass
class ScanResult:
    """The full result of scanning one repo."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def sorted_findings(self) -> list[Finding]:
        # Severity first (P0..P3), then confidence (high..low), then path.
        conf_rank = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, conf_rank[f.confidence], f.file, f.line),
        )

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def clean_bill(self) -> bool:
        """A clean bill of health == no critical/high (P0/P1) findings.

        Medium/low informational findings are allowed; this mirrors how the
        fleet audit called servers "clean" despite P2/P3 hardening nits.
        """
        return not any(f.severity in (Severity.P0, Severity.P1) for f in self.findings)

    def to_dict(self) -> dict:
        # Assign each finding its stable finding_id (class+file+normalized
        # title, line-independent -- see finding_identity.py) in emitted
        # order, so collision suffixes are deterministic.
        from .finding_identity import assign_finding_ids

        ordered = self.sorted_findings
        ids = assign_finding_ids([(f.vuln_class, f.file, f.title) for f in ordered])
        finding_dicts = []
        for fid, f in zip(ids, ordered):
            d = f.to_dict()
            d["finding_id"] = fid
            finding_dicts.append(d)
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "counts_by_severity": self.counts_by_severity(),
            "clean_bill": self.clean_bill,
            "findings": finding_dicts,
            "errors": self.errors,
        }
