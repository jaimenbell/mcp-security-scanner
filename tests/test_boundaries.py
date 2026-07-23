"""Structured honest-capability-boundary constant (spec 2026-07-23).

Single source for the client report's Methodology section, seeded one-time
from README.md's "Honest capability boundary" section (README keeps its own
prose; sync deferred by design -- v1 does not rewrite the README).
"""
from __future__ import annotations

from mcp_scanner.boundaries import CAPABILITY_BOUNDARY


def test_boundary_is_structured_nonempty_list():
    assert isinstance(CAPABILITY_BOUNDARY, list)
    assert len(CAPABILITY_BOUNDARY) >= 6
    for entry in CAPABILITY_BOUNDARY:
        assert set(entry) == {"title", "body"}
        assert entry["title"].strip() and entry["body"].strip()


def test_boundary_is_ascii_only():
    for entry in CAPABILITY_BOUNDARY:
        (entry["title"] + entry["body"]).encode("ascii")


def test_boundary_carries_the_core_honesty_claims():
    """The load-bearing disclosures from the README section must survive
    the structuring: static-only, no git history, confidence philosophy,
    taint limits, JS/TS regex level, and the one law."""
    text = " ".join(e["title"] + " " + e["body"] for e in CAPABILITY_BOUNDARY).lower()
    for needle in (
        "static",            # static only, no dynamic analysis
        "git-history",       # not a git-history scanner
        "gitleaks",
        "confidence",        # confidence is load-bearing
        "taint",             # taint v1 + its limits
        "sanitizer",         # not sanitizer-aware
        "regex",             # JS/TS is regex-level, no AST parity
        "never",             # never drops a finding / never disappears
    ):
        assert needle in text, f"boundary lost the '{needle}' disclosure"
