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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
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
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "counts_by_severity": self.counts_by_severity(),
            "clean_bill": self.clean_bill,
            "findings": [f.to_dict() for f in self.sorted_findings],
            "errors": self.errors,
        }
