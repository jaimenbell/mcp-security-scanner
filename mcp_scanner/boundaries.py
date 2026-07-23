"""The scanner's honest capability boundary, as a structured constant.

Seeded ONE-TIME (2026-07-23) from README.md's "Honest capability boundary"
section, condensed for client-report rendering -- each entry keeps the
load-bearing disclosure, not the full engineering history. The README
continues to carry its own long-form prose; syncing the two is deliberately
deferred (v1 does not rewrite the README).

This module is CONTENT: the operator may edit entries freely post-merge.
The report generator renders whatever is here -- it never invents
methodology claims of its own.

HARD RAIL -- presentation only: nothing here changes detection logic.
"""
from __future__ import annotations

# Each entry: {"title": ..., "body": ...}. Rendered in order in the
# report's "Methodology & honest capability boundary" section.
CAPABILITY_BOUNDARY: list[dict[str, str]] = [
    {
        "title": "Static analysis only",
        "body": (
            "Every finding comes from reading the target's git-tracked "
            "source (Python AST for the deep path; regex for Jinja/JS/TS/"
            "YAML/PowerShell/bash surfaces). No code is executed, no server "
            "is run, and no finding is proven exploitable at runtime -- "
            "findings are a prioritized review queue, not a verdict."
        ),
    },
    {
        "title": "Manifest-aware tool reachability grading",
        "body": (
            "After the detectors run, the scanner discovers registered MCP "
            "tools (decorator registrations, the low-level SDK's "
            "Server()/list_tools/call_tool shape, and any server.json "
            "manifest) and walks a static call-graph to label each finding "
            "reachable, cli-only, uncalled, or unknown. Reachable raises a "
            "finding's confidence; the others lower it; a finding is never "
            "dropped on this basis. Limits: the same-file call-graph is "
            "exact, cross-file is best-effort; module-level code, "
            "non-Python findings, ambiguous low-level-SDK dispatch, and "
            "repos with no discoverable tools are labelled unknown rather "
            "than guessed."
        ),
    },
    {
        "title": "Tool-parameter taint tracking v1",
        "body": (
            "A second pass seeds every registered tool handler's "
            "parameters as taint sources and propagates them through "
            "assignments, f-strings/concat/format, containers, and "
            "same-repo calls into the dangerous sinks, labelling findings "
            "tainted / untainted / unknown (again nudging confidence, "
            "never dropping). Limits, stated plainly: same-file dataflow "
            "is transitive but cross-file follows at most two direct-"
            "import hops (no third hop, no cross-repo flow); it is NOT "
            "sanitizer-aware (a validated/escaped value still counts as "
            "tainted, by design over-flagging); and dynamic dispatch "
            "(getattr / *args / **kwargs), decorator transforms, and "
            "non-Python surfaces are labelled unknown."
        ),
    },
    {
        "title": "Confidence is load-bearing",
        "body": (
            "This is a deliberately over-flagging scanner: low-confidence "
            "findings mean 'a human should glance at this' and produce "
            "false positives by design. The triage pass in this report is "
            "where a human separates the two -- the raw finding count is "
            "not the risk count."
        ),
    },
    {
        "title": "The one law of suppression",
        "body": (
            "Full suppression is reserved for the scanner's OWN curated "
            "exact-match judgment (e.g. documented SDK placeholder "
            "credentials, pagination-cursor field names, provably "
            "self-signed test certificates with test-identity CN/SAN). "
            "Every other signal -- a target-authored suppress comment, an "
            "obviously-fake value marker, a cert's test path -- may only "
            "demote confidence and tag the finding; it may never make a "
            "finding disappear. This matters because the scanner's use "
            "case is third-party, possibly-adversarial repos."
        ),
    },
    {
        "title": "Not a git-history scanner",
        "body": (
            "The secret detector reads the tracked working tree only -- it "
            "does not see credentials that were committed and later "
            "removed. Pair it with gitleaks for history scanning."
        ),
    },
    {
        "title": "Language coverage",
        "body": (
            "Deep (AST-based) for Python. JS/TS (.js/.mjs/.cjs/.ts/.mts/"
            ".cts/.jsx/.tsx) is line-based regex, not a parse tree: four "
            "detector families have JS/TS parity on that regex basis "
            "(param-injection, tool-scope-creep, secret-leak-via-tool-"
            "response, secret-in-log), while codegen-injection and "
            "auth-posture remain Python-only by scope decision. Jinja "
            "templates are regex-level. Known regex-heuristic gaps (e.g. "
            "optional-chaining eval, spread-of-secret returns) are "
            "documented in the README rather than silently missed."
        ),
    },
    {
        "title": "Every finding needs a human",
        "body": (
            "No dynamic analysis means no proof of exploitability: every "
            "finding in this report was either confirmed, dismissed, or "
            "left unreviewed by a named human triage pass, and the report "
            "says which, per finding. A clean bill means no critical/high "
            "patterns were found by these detectors -- not a guarantee of "
            "security."
        ),
    },
]
