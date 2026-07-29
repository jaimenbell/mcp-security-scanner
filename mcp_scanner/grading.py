"""Grading honesty (final post-detector pass).

WHY THIS EXISTS
---------------
A held-out measurement on 2026-07-29 ran this scanner against five pinned
third-party MCP servers and scored **0 true positives out of 58 findings**.
The root cause was not a broken detector. It was this:

    ``reachability.py`` and ``taint.py`` both return UNKNOWN unless the file
    is ``.py``/``.pyw``. So every JS/TS finding was raw pattern output with
    neither precision layer applied -- and the report rendered it IDENTICALLY
    to a properly-graded Python finding. Same severity badge, same confidence
    field, no visible difference. Four P0s in the sample rested on a regex
    match and nothing else, and a reader of the report had no way to know.

    The single Python target in that sample returned a clean bill. The
    scanner was not broadly broken; its JS/TS path simply had no precision
    layer, and said nothing about that.

That is a *reporting* defect as much as an analysis one, and this pass fixes
the reporting half. It is the last pass in ``scan_repo``, after reachability
and taint, because it reads their verdicts.

THE RULE
--------
A finding is ``UNGRADED`` when BOTH precision axes came back UNKNOWN --
nothing whatsoever was established beyond the pattern match. Deliberately
expressed as an OUTCOME, not a language check: that covers JS/TS/YAML/shell
findings, and equally a Python finding in a repo with no discoverable tool
registrations (which honestly is also "we established nothing"). An
outcome-shaped rule cannot fall out of date as new surfaces are added, the
way an explicit language list would.

THE LABEL AND THE CAP ARE SEPARATE, WITH SEPARATE SCOPES
--------------------------------------------------------
A rule shipped without its scope silently defaults to "everywhere", so both
are stated here, next to the code that implements them.

**The LABEL is outcome-based and broad.** Both axes UNKNOWN -> UNGRADED. It
is a statement of fact ("nothing was established beyond the pattern") and
carries no consequence of its own, so breadth is free and honesty is served.

**The CAP is capability-based and narrow.** It applies only where BOTH hold:

  1. The FILE could not be analysed at all -- a non-Python surface with no
     AST, a Python file that failed to parse, or a file missing from the
     parsed set. This is a capability gap: nothing was even attempted.

  2. The vuln_class is one of the dataflow classes, imported from ``taint``
     itself rather than copied so the two cannot drift. For shell-injection /
     code-eval / unsafe-deserialization / ssrf / path-traversal the severity
     ladder IS a dataflow claim -- "P0 = exploitable now, no preconditions"
     asserts that caller-controlled data reaches the sink, exactly what the
     taint pass exists to establish. With no dataflow pass possible, P0 is
     unearned, so the finding is capped at P2/LOW.

WHY THE CAP IS *NOT* MERELY "BOTH AXES UNKNOWN" (the distinction that matters,
and the first version of this pass got it wrong): reachability and taint also
return UNKNOWN when they DID run and deliberately DECLINED to assert --
module-level code, dynamic dispatch present, an un-rooted low-level-SDK
dispatcher, or a repo with no discoverable tool roots. Those are
soundness-over-decidability withholdings, and this repo has an explicit,
N-vote-adjudicated contract that they must leave confidence untouched
("honest UNKNOWN rather than a guess in either direction"). Capping there
would convert a principled abstention into a downgrade -- a guess in one
direction, and a regression against a reviewed invariant. So the cap keys on
whether the file was ANALYSABLE, never on whether the answer was decided.

The cap is also OUT OF SCOPE for every non-dataflow class -- hardcoded-secret,
secret-in-log, auth-posture, job-*, tool-scope-creep. A committed AWS key is a
P1 whether or not any registered tool reaches it; that severity never rested
on a reachability claim, so capping it would be dishonest in the other
direction and would cost real recall on the class a client most wants to hear
about. Those findings are still LABELLED ungraded.

Nothing is ever dropped. README's one law stands: this labels, explains, and
(narrowly) caps -- it does not suppress.
"""

from __future__ import annotations

from dataclasses import replace

from .detectors.base import RepoContext
from .models import (Confidence, Finding, Grade, Reachability, ScanResult,
                     Severity, Taint)
from .taint import _DATAFLOW_CLASSES
from .tool_registry import extract_tool_registry

# The classes whose SEVERITY is a dataflow claim, and therefore the only ones
# the cap applies to. Bound to taint's own set (identity, not a copy) so the
# justification and the rule can never drift apart.
_CAPPED_CLASSES = _DATAFLOW_CLASSES

# Ungraded dataflow findings land here. P2 == "defense-in-depth gap /
# conditional", which is an honest description of a pattern hit whose
# exploitability was never examined.
_SEVERITY_CAP = Severity.P2

# Surfaces the precision passes can analyse at all.
_GRADABLE_SUFFIXES = (".py", ".pyw")


def grade_result(ctx: RepoContext, result: ScanResult) -> None:
    """In-place: label every finding GRADED/UNGRADED with a reason, apply the
    scoped severity cap, and record per-run coverage on the result."""
    has_tools = bool(extract_tool_registry(ctx))
    by_rel = {f.rel: f for f in ctx.files}

    graded: list[Finding] = []
    n_ungraded = 0
    for f in result.findings:
        if f.reachability is not Reachability.UNKNOWN or f.taint is not Taint.UNKNOWN:
            graded.append(replace(f, grade=Grade.GRADED, grade_reason=""))
            continue
        n_ungraded += 1
        src = by_rel.get(f.file)
        reason = _reason_for(f, src, has_tools)
        sev, conf, detail = f.severity, f.confidence, f.detail
        # THE CAP. Both conditions required -- see the module docstring for
        # why "both axes UNKNOWN" alone is the wrong trigger.
        if _file_is_unanalysable(src) and f.vuln_class in _CAPPED_CLASSES:
            conf = Confidence.LOW
            if f.severity.rank < _SEVERITY_CAP.rank:
                sev = _SEVERITY_CAP
                detail = (
                    f"{detail} SEVERITY CAPPED: this finding was reported at "
                    f"{f.severity.value} by pattern match alone. {reason} For "
                    "this vulnerability class the severity ladder is itself a "
                    "dataflow claim -- 'exploitable now' asserts that "
                    "caller-controlled data reaches this sink -- so with no "
                    "dataflow analysis possible on this file it is capped at "
                    f"{_SEVERITY_CAP.value}/low rather than presented at a "
                    "severity the evidence does not support."
                )
        graded.append(replace(f, grade=Grade.UNGRADED, grade_reason=reason,
                              severity=sev, confidence=conf, detail=detail))
    result.findings = graded
    result.coverage = _coverage(ctx, has_tools, len(graded) - n_ungraded, n_ungraded)


def _file_is_unanalysable(src) -> bool:
    """True when the precision passes had no way to analyse this file AT ALL.

    A capability gap, not a decidability one -- this is deliberately blind to
    whether the passes reached a verdict, because a principled abstention on
    an analysable file must not be treated the same as a surface the scanner
    cannot read. Sole trigger for the severity cap.
    """
    if src is None:
        return True
    return src.suffix not in _GRADABLE_SUFFIXES or src.tree is None


def _reason_for(f: Finding, src, has_tools: bool) -> str:
    """A specific, checkable reason -- never a generic 'unknown'.

    Ordered most-specific-first so the reason names the FIRST wall the passes
    actually hit, which is the one a reader would need to remove.
    """
    if src is None:
        return ("the flagged file was not present in the parsed file set, so "
                "no call-graph or dataflow analysis could be attached to it.")
    suffix = src.suffix or "(no extension)"
    if suffix not in _GRADABLE_SUFFIXES:
        return (f"non-Python surface ({suffix}): the scanner has no call-graph "
                "or dataflow analysis for this language, so this finding is "
                "raw pattern-match output. A validator or sanitiser adjacent "
                "to the flagged line would NOT have been seen.")
    if src.tree is None:
        return (f"the file is Python ({suffix}) but could not be parsed, so no "
                "AST call-graph was available for it.")
    if not has_tools:
        return ("no MCP tool registrations were found in this repo, so there "
                "is nothing for the flagged code to be reachable *from* and "
                "no tool parameters to seed dataflow with.")
    if f.line <= 0:
        return ("whole-file finding with no single code location, so it cannot "
                "be attributed to a call path.")
    return ("the call-graph and dataflow passes ran but could not decide -- "
            "typically module-level code, or dynamic dispatch elsewhere in the "
            "repo that could hide a call path (soundness over decidability).")


def _coverage(ctx: RepoContext, has_tools: bool, n_graded: int,
              n_ungraded: int) -> dict:
    """Per-run answer to 'which files could you not grade, and why?'."""
    reasons: dict[str, int] = {}
    gradable = 0
    for src in ctx.files:
        suffix = src.suffix or "(no extension)"
        if suffix not in _GRADABLE_SUFFIXES:
            key = (f"non-Python surface ({suffix}): no call-graph or dataflow "
                   "analysis exists for this language")
        elif src.tree is None:
            key = f"Python file ({suffix}) that could not be parsed"
        elif not has_tools:
            key = ("no MCP tool registrations found in this repo: nothing to "
                   "be reachable from")
        else:
            gradable += 1
            continue
        reasons[key] = reasons.get(key, 0) + 1
    return {
        "gradable_files": gradable,
        "ungradable_files": len(ctx.files) - gradable,
        "ungradable_files_by_reason": dict(
            sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
        "tool_registrations_found": has_tools,
        "findings_graded": n_graded,
        "findings_ungraded": n_ungraded,
    }
