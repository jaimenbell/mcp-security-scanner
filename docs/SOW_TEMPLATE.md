---
title: "Statement of Work -- One-Shot MCP Security Audit (fill-in template)"
type: sow-template
audience: client-facing (fill the [brackets] and send)
version: 2026-07-22
spec: "mcp-security-scanner-retainer-spec-2026-07-16.md §2-3"
capability_boundary: "the Capability statement below is quoted VERBATIM from mcp_scanner/client_report.py's CAPABILITY_STATEMENT"
tags: [mcp-security-scanner, sow, template, one-shot-audit]
---

# Statement of Work -- One-Shot MCP Security Audit

> Fill every `[bracket]`. The Capability statement and Scope rails are
> fixed -- do not edit them; they are the contractual honesty boundary and
> the same words the delivered report uses.

**Client:** `[Client legal name]`
**Provider:** `[Your name / entity]`
**Engagement:** One-Shot MCP Security Audit (standalone)
**Fee:** `[$250-750 USD, fixed -- see §Pricing path]`
**Term:** `[1-3 business days]` from kickoff
**Effective date:** `[date]`

---

## 1. What this engagement is

A read-only static security scan of `[Client]`'s MCP server repo, plus a
hand-reviewed 8-section consulting report separating true positives from
heuristic noise, with concrete fixes.

**In-scope stack:** `[the MCP server repo(s) named here]`, git-tracked
Python/Jinja source (AST-based) plus JS/TS/YAML/PowerShell/bash source
(regex-based) -- see the Capability statement below for exactly which
detector families run on which surface.

**Access model:** `[read-only repo clone | supervised screen-share]`. The
Provider does not run, deploy, or execute anything in `[Client]`'s stack.

---

## 2. Capability statement (verbatim -- the honesty boundary)

> This clause defines exactly what is tooled versus expert-led. It is not
> marketing; it is the scope of the deliverable.

**What the tool genuinely did.** It read the git-tracked source of the
target repo (Python AST for the deep path, regex for Jinja/JS/TS/YAML/
PowerShell/bash) and ran seven detector families -- codegen/template
injection, tool-param injection, auth/network posture, secret handling,
tool-scope-creep (mutating `@mcp.tool()`-registered tools with no visible
permission gate), secret-leak-via-tool-response (a tool's own `return`
value leaking a credential or a whole config/environment dump back to the
calling LLM), and job-hazards (over-broad scope, unconfirmed destructive
calls, and unverified-success patterns in scheduled jobs, wrappers, and
IaC/CI files) -- producing the severity- and confidence-ranked findings
table above with a file:line for each hit. It then graded each finding for
MCP-tool reachability: it discovered the registered tools (`@mcp.tool()` /
`server.tool(...)` registrations and any `server.json` manifest) and walked a
static call-graph to label whether each finding sits on code reachable from a
tool (same-file exact, cross-file best-effort), nudging confidence up for
reachable hits and down for unreachable ones. It then ran tool-parameter
taint tracking v1: it seeded each registered tool handler's parameters as
taint sources and propagated them through assignments, f-strings/concat/
format, containers and same-repo calls into the dangerous sinks -- same-file
transitively, up to two direct-import hops cross-file -- labelling each finding
tainted / untainted / unknown and again nudging confidence (up for tainted,
down for untainted), never dropping a finding.

**What was expert-led (not the tool).** Separating true positives from
low-confidence heuristic noise; confirming a finding is actually
reachable from an attacker-controlled input; the fix-shape and ranked
fix-lane plan below.

**What it does NOT do -- stated plainly.** No dynamic analysis. The taint
pass is v1: it follows only up to TWO cross-file import hops (no third hop, no
cross-repo flow), it is NOT sanitizer-aware (a validated/escaped value is
still treated as tainted, by design over-flagging), and it does not model
dynamic dispatch (getattr / *args / **kwargs). So it is honest tool-parameter
taint tracking with a stated boundary, not deep whole-program taint.
No git-history secret scanning (pair with `gitleaks`). No JS/TS AST parity
(regex-level only; JS findings are labelled reachability- and
taint-unknown). See the Detector-class reference below for the full
built-vs-not-built breakdown.

*(The "above"/"below" references match this text's placement in the
delivered report, D1 §5-7; in this SOW they refer to that same report.)*

---

## 3. Deliverables

| # | Deliverable | Contents |
|---|---|---|
| D1 | Client-facing report | 8-section report: exec summary in plain incident language, top-3-to-fix, findings table (file:line · severity · class · remediation · confidence), critical-evidence appendix, detector-class reference (all seven classes), Capability statement verbatim, ranked fix-lane plan. |
| D2 | Raw JSON | Machine-readable findings for your own tooling / CI, via `mcp-scan <path> --json`. |
| D3 | Ranked fix-lane plan | Findings sequenced by severity, each with a concrete fix-shape. Doubles as the scope of a follow-on fix engagement. |

---

## 4. Acceptance gate

- Every P0 (critical) finding includes a reproducible check `[Client]` can
  re-run independently (the flagged snippet, verifiable in the JSON
  output).
- No finding is delivered without a file:line.
- Nothing in `[Client]`'s stack was modified, deleted, or executed
  (read-only, static analysis only).

---

## 5. Scope rails (explicitly NOT included)

- **No dynamic/runtime analysis.** Static source read only; the server is
  never run.
- **No taint tracking past two cross-file import hops.** Same-file
  dataflow is transitive; cross-file taint stops at the second hop (no
  third hop, no cross-repo flow), and it is not sanitizer-aware (a
  validated value is still treated as tainted, by design). Reachability
  grading is separate and covers same-file exact / cross-file
  best-effort by function name.
- **No full JS/TS AST parity.** Today's JS/TS coverage is regex/heuristic,
  covering four of the seven detector families; codegen-injection and
  auth-posture stay Python-only by scope decision, and JS/TS findings are
  labelled reachability- and taint-unknown.
- **No git-history secret scanning.** Pair with `gitleaks` for history;
  not rebuilt here.
- **No hosted/SaaS dashboard.** CLI + CI gate (`--fail-on P1`) only.
- **Boundary = the repo named in §1.** Anything outside it is a new quote.

---

## 6. Schedule

| Day | Milestone |
|---|---|
| 0 | Kickoff; access model agreed; repo scoped. |
| 1 | Scan run; candidate findings generated. |
| 1-2 | Expert triage (true-positive vs. heuristic noise). |
| 2-3 | Report assembly; acceptance readout. |

---

## 7. Pricing path

- **This engagement:** `[$250-750 fixed, band per repo size/complexity]`.
- **CI-gate Watch** (optional, separately scoped): $99-149/mo.
- **Fix-it add-on** (optional): scoped per finding, priced after D3 is
  delivered.

---

## 8. Signatures

`[Client]` -- `[name / title / date]`

`[Provider]` -- `[name / date]`
