"""client_report.py -- the 8-section client-facing consulting report.

Ports the *structure* of reliability-retainer's ``tools/report.py`` into
this repo's own idiom (see mcp-security-scanner-retainer-spec-2026-07-16.md
§3: "port the pattern, not the code" -- the two repos' Finding dataclasses
are separately implemented and there is no direct import reuse across the
two products).

Turns the raw, severity-sorted ``ScanResult`` into a consulting deliverable
a founder can read -- not a pattern dump:

  1. Header             -- client, date, scope boundary, read-only notice,
                            severity legend, generated counts
  2. Executive summary  -- top risk in plain MCP-incident language
  3. Top 3 to fix        -- highest severity, plain English
  4. Findings by severity table -- + remediation + confidence columns
  5. Critical evidence appendix -- a reproducible proof per P0 (no P0
                                    without one)
  6. Detector-class reference -- what the 6 built detectors cover, plus an
                                  explicit, honest disclosure of what this
                                  scanner still does NOT detect (cross-file
                                  taint, git-history secrets, JS/TS AST
                                  parity, dynamic analysis)
  7. Scope & method     -- the capability statement, VERBATIM
  8. Ranked fix-lane plan -- doubles as the next quote

Framing rules: one plain sentence per finding lead (vuln_class id is a
trailing tag, never the lead); severity legend defined once; every
quantitative claim (counts) is GENERATED, never hand-typed -- no drift.

HARD RAIL -- ZERO EFFECTORS: this module only reads a ``ScanResult`` and
returns a string. It never writes to / deletes from / executes against a
scanned target. Enforced by
tests/test_client_report.py::test_client_report_module_has_no_effector_shaped_symbol.
"""
from __future__ import annotations

import datetime as dt

from .models import ScanResult, Finding, Severity, Confidence

# --------------------------------------------------------------------- #
# Static vocabulary
# --------------------------------------------------------------------- #

SEVERITY_LEGEND = [
    ("P0", "Critical -- exploitable now, no preconditions"),
    ("P1", "High -- exploitable with attacker-reachable but currently-unmet conditions"),
    ("P2", "Medium -- defense-in-depth gap / conditional"),
    ("P3", "Low -- hardening nit"),
]

# vuln_class -> plain-English incident lead used in the executive summary,
# so the summary reads as a finding, not a machine id.
VULN_CLASS_INCIDENT_LANG = {
    "codegen-injection": "a code-generating tool that renders untrusted "
                          "input into generated source without a real "
                          "serializer or autoescape",
    "param-injection": "a tool handler that passes caller-influenced input "
                        "into a dangerous sink (shell, eval, unsafe "
                        "deserialization, or an unguarded fetch/file path)",
    "auth-posture": "a networked server with a mutating route and no "
                     "visible auth gate or rate limiter",
    "secret-handling": "a secret committed to the tree, hardcoded in "
                        "source, or passed to a log/print call",
    "tool-scope-creep": "a mutating MCP tool registered with no visible "
                         "permission-group gate or env-flag opt-in",
    "secret-leak-via-tool-response": "a tool response that hands a "
                                      "credential or a whole config/"
                                      "environment dump back to the "
                                      "calling LLM",
    "job-overbroad-scope": "a scheduled job or wrapper granted broader "
                            "credential/ACL scope than it needs",
    "job-destructive-no-confirm": "a destructive call in a scheduled job "
                                   "or wrapper with no confirm-before-"
                                   "destroy gate",
    "job-unverified-success": "a job that can report success without "
                               "verifying what it actually did",
}

DETECTOR_CLASS_TABLE = [
    ("codegen-injection", "Jinja `autoescape` off in a code-generating tool; "
                           "hand-rolled string escaping instead of a real serializer."),
    ("param-injection", "`subprocess(shell=True)`, `os.system`, non-constant "
                         "`eval`/`exec`, `pickle.load`, unsafe `yaml.load`, SSRF, "
                         "path traversal."),
    ("auth-posture", "Bind `0.0.0.0` (+debug escalation), `debug=True`, mutating "
                      "routes with no auth dependency, no rate limiter."),
    ("secret-handling", "Tracked `.env`/`.pem`/`.key`/keypair files, hardcoded "
                         "secret-shaped literals, secrets passed to `print`/`log.*`."),
    ("tool-scope-creep", "A mutating `@mcp.tool()`-registered tool (by verb-name "
                          "heuristic or a dangerous body sink, one hop through a "
                          "delegated helper) with no visible permission-group gate "
                          "or env-flag opt-in anywhere in its file or the helper it "
                          "calls."),
    ("secret-leak-via-tool-response", "A tool's `return` value that hands back "
                                       "`os.environ`, a whole config/settings object "
                                       "(`vars()`/`asdict()`/`__dict__`), a "
                                       "secret-named field, or a hardcoded "
                                       "secret-shaped literal to the calling LLM."),
    ("job-hazards", "Scheduled jobs/wrappers/IaC-CI files (cron, systemd, GitHub "
                     "Actions, PowerShell/bash/batch deploy scripts): over-broad "
                     "credential/ACL scope, a destructive call with no "
                     "confirm-before-destroy gate, and success reported without "
                     "verification (`|| true`, bare `exit 0`, `continue-on-error`, "
                     "empty `catch {}`)."),
]

# Historical note: this list used to carry write-tools-on-by-default /
# tool-scope-creep and secret-leak-via-tool-response as NOT yet built --
# both shipped 2026-07-19 (mcp-security-scanner-retainer-spec-2026-07-16.md
# §1.2/§4 Phase 1) and now have their own rows in DETECTOR_CLASS_TABLE
# above. What's left here is the genuinely still-true, deliberately
# out-of-scope list (spec §1.3 / this repo's own PRODUCT.md), stated
# plainly so the report never overclaims coverage it doesn't have.
NOT_YET_BUILT = [
    ("Cross-file/cross-repo taint tracking",
     "whether a value flows from an untrusted tool argument, through "
     "another file or module, into a dangerous sink -- every detector "
     "above is a same-file (or, for tool-scope-creep, one-hop) heuristic, "
     "not a real call graph"),
    ("Git-history secret scanning",
     "whether a credential was ever committed and later removed -- this "
     "scan only sees the current git-tracked working tree (pair with "
     "`gitleaks` for history)"),
    ("Full JS/TS AST parity",
     "the JS/TS surface stays regex-level rather than a real parse tree, "
     "so some patterns the Python AST path catches precisely are only "
     "regex-approximated there"),
    ("Any dynamic/runtime analysis",
     "whether a flagged pattern is actually reachable and exploitable at "
     "runtime -- this is a static scan by design; every finding still "
     "needs a human to confirm reachability"),
]

SELF_SERVE_CHECKLIST = [
    "Enable autoescape (or use a real serializer) in any tool that generates code.",
    "Never `shell=True`; never `eval`/`exec` on a non-constant; use `SafeLoader` for YAML.",
    "Gate every mutating tool behind an explicit auth check or permission-group flag.",
    "Never bind `0.0.0.0` with `debug=True`; put a rate limiter in front of mutating routes.",
    "Never commit `.env`/`.pem`/`.key` files; never pass a secret to `print`/`log.*`.",
    "Review what a tool's `return` value actually sends back to the calling LLM.",
]

# The honest capability boundary -- quoted VERBATIM into the SOW and this
# report so the tool-vs-expert split is contractual, not verbal. Mirrors
# reliability-retainer's tools/report.py CAPABILITY_STATEMENT shape,
# re-skinned for this scanner's real detectors and real gaps.
CAPABILITY_STATEMENT = """\
**What the tool genuinely did.** It read the git-tracked source of the \
target repo (Python AST for the deep path, regex for Jinja/JS/TS/YAML/ \
PowerShell/bash) and ran seven detector families -- codegen/template \
injection, tool-param injection, auth/network posture, secret handling, \
tool-scope-creep (mutating `@mcp.tool()`-registered tools with no visible \
permission gate), secret-leak-via-tool-response (a tool's own `return` \
value leaking a credential or a whole config/environment dump back to the \
calling LLM), and job-hazards (over-broad scope, unconfirmed destructive \
calls, and unverified-success patterns in scheduled jobs, wrappers, and \
IaC/CI files) -- producing the severity- and confidence-ranked findings \
table above with a file:line for each hit.

**What was expert-led (not the tool).** Separating true positives from \
low-confidence heuristic noise; confirming a finding is actually \
reachable from an attacker-controlled input; the fix-shape and ranked \
fix-lane plan below.

**What it does NOT do -- stated plainly.** No dynamic analysis. No \
cross-file/cross-repo taint tracking (same-file heuristics only, with one \
deliberate one-hop exception in tool-scope-creep for a directly-called \
gating helper). No git-history secret scanning (pair with `gitleaks`). No \
JS/TS AST parity (regex-level only). See the Detector-class reference \
below for the full built-vs-not-built breakdown."""


# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #
def _first_sentence(detail: str) -> str:
    """One clear sentence -- the finding lead. Splits on the first
    ' -- ' clause or the first period."""
    msg = detail.strip()
    for sep in (" -- ", ". "):
        if sep in msg:
            head = msg.split(sep, 1)[0].strip()
            if head:
                return head[0].upper() + head[1:]
    return msg.rstrip(".")


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _p0_proof(f: Finding) -> str:
    """A reproducible-proof recipe per P0 -- the shape a client can re-run
    themselves against their own tree."""
    return (
        f"Re-run `mcp-scan <path> --json` and inspect the `{f.vuln_class}` "
        f"finding at `{f.file}:{f.line}` -- the flagged line is included "
        "verbatim in the JSON output (`snippet` field), so the pattern is "
        "checkable without re-running the scanner: "
        f"`{f.snippet or '(see file:line above)'}`."
    )


def _counts(findings: list[Finding]) -> dict[str, int]:
    c = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for f in findings:
        c[f.severity.value] = c.get(f.severity.value, 0) + 1
    return c


# --------------------------------------------------------------------- #
# Renderer
# --------------------------------------------------------------------- #
def render_client_report(result: ScanResult, client_name: str = "the client",
                          scope_boundary: str | None = None,
                          now: "dt.datetime | None" = None) -> str:
    findings = result.sorted_findings
    counts = _counts(findings)
    total = len(findings)
    now = now or dt.datetime.now()
    date_s = now.strftime("%Y-%m-%d")
    boundary = scope_boundary or (
        f"the supplied MCP server repo at `{result.target}` -- trading/business "
        "logic, model quality, and infra ops are explicitly out of scope."
    )
    p0s = [f for f in findings if f.severity == Severity.P0]

    L: list[str] = []

    # 1. Header ---------------------------------------------------------- #
    L += [
        f"# MCP Server Security Audit -- {client_name}",
        "",
        f"**Date:** {date_s}  ",
        f"**Scope boundary:** {boundary}  ",
        "**Method:** Read-only static scan. No file in the target was modified, "
        "deleted, or executed. Every finding carries a file:line; every P0 "
        "critical includes a reproducible proof you can verify yourself.",
        "",
        f"**Findings: {total} total** -- P0: {counts['P0']}, P1: {counts['P1']}, "
        f"P2: {counts['P2']}, P3: {counts['P3']}.",
        "",
        "**Severity legend:** "
        + "; ".join(f"**{s}** = {d}" for s, d in SEVERITY_LEGEND) + ".",
        "",
    ]

    # 2. Executive summary ------------------------------------------------ #
    L += ["## 1. Executive summary", ""]
    if findings:
        top = findings[0]
        incident = VULN_CLASS_INCIDENT_LANG.get(
            top.vuln_class, "a flagged risky pattern")
        L += [
            f"We scanned `{_short(result.target)}` ({result.files_scanned} source "
            f"files) and found **{total} finding{'s' if total != 1 else ''}** "
            f"({counts['P0']} critical, {counts['P1']} high). The most serious "
            f"class is **{incident}**. Each critical below includes a "
            "reproducible proof you can check yourself, and the closing "
            "fix-lane plan sequences the remediation work.",
        ]
    else:
        L += ["We scanned the supplied repo and found no findings in the "
              "tooled detector set. The Scope & method section states what "
              "that does and does not prove."]
    L += [""]

    # 3. Top 3 to fix ------------------------------------------------------ #
    L += ["## 2. Top 3 to fix", ""]
    if findings:
        for n, f in enumerate(findings[:3], start=1):
            L.append(f"{n}. **[{f.severity.value}] `{f.file}:{f.line}`** -- "
                     f"{_first_sentence(f.detail)}. "
                     f"_Fix:_ {f.remediation or 'see finding.'}")
    else:
        L.append("_No findings._")
    L += [""]

    # 4. Findings by severity ---------------------------------------------- #
    L += [
        "## 3. Findings by severity",
        "",
        "| File:Line | Severity | Class | What it is | Remediation | Confidence |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        L.append(
            f"| `{f.file}:{f.line}` | {f.severity.value} | `{f.vuln_class}` "
            f"| {_md_cell(_first_sentence(f.detail))} "
            f"| {_md_cell(f.remediation or '--')} "
            f"| {f.confidence.value} |"
        )
    if not findings:
        L.append("| -- | -- | -- | _no findings_ | -- | -- |")
    L += [""]

    # 5. Critical evidence appendix ----------------------------------------- #
    L += ["## 4. Critical evidence appendix", ""]
    if p0s:
        L += ["Every P0 below is reproducible with a read-only check -- "
              "no P0 is asserted without one.", ""]
        for f in p0s:
            L += [
                f"### `{f.file}:{f.line}` -- {_first_sentence(f.detail)} "
                f"<sub>(`{f.vuln_class}`)</sub>",
                "",
                f"- **Why it's critical:** {f.detail}",
                f"- **Reproducible proof:** {_p0_proof(f)}",
                f"- **Fix:** {f.remediation or 'see finding.'}",
                "",
            ]
    else:
        L += ["No P0 (critical) findings in this scan.", ""]

    # 6. Detector-class reference -------------------------------------------- #
    L += ["## 5. Detector-class reference", ""]
    L += ["What this scan actually checked, and an honest disclosure of "
          "what it does not check yet.", ""]
    L += ["**Built and checked in this scan:**", ""]
    for vc, desc in DETECTOR_CLASS_TABLE:
        L.append(f"- **`{vc}`** -- {desc}")
    L += [""]
    L += ["**NOT yet built -- not checked in this scan:**", ""]
    for name, desc in NOT_YET_BUILT:
        L.append(f"- **{name}** -- {desc}.")
    L += [""]
    L += ["**6-point self-serve checklist:**", ""]
    for n, item in enumerate(SELF_SERVE_CHECKLIST, start=1):
        L.append(f"{n}. {item}")
    L += [""]

    # 7. Scope & method (verbatim capability statement) ---------------------- #
    L += ["## 6. Scope & method", "", CAPABILITY_STATEMENT, ""]

    # 8. Ranked fix-lane plan --------------------------------------------------- #
    L += ["## 7. Ranked fix-lane plan (doubles as the next quote)", ""]
    if findings:
        L += ["Sequenced by severity. This plan is the scope of a follow-on "
              "remediation engagement -- each lane is an independently-"
              "shippable fix.", ""]
        for n, f in enumerate(findings, start=1):
            L.append(
                f"{n}. **[{f.severity.value}] `{f.file}:{f.line}`** "
                f"(`{f.vuln_class}`) -- {f.remediation or _first_sentence(f.detail)}"
            )
    else:
        L.append("_No remediation lanes -- no findings._")
    L += [""]

    return "\n".join(L)


def _short(path: str) -> str:
    p = path.replace("\\", "/")
    return p.rsplit("/", 1)[-1] or p
