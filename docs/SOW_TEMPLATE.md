---
title: "Statement of Work -- One-Shot MCP Security Audit (fill-in template)"
type: sow-template
audience: client-facing (fill the [brackets] and send)
version: 2026-07-16
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
Python/Jinja/JS/TS source only.

**Access model:** `[read-only repo clone | supervised screen-share]`. The
Provider does not run, deploy, or execute anything in `[Client]`'s stack.

---

## 2. Capability statement (verbatim -- the honesty boundary)

> This clause defines exactly what is tooled versus expert-led. It is not
> marketing; it is the scope of the deliverable.

**What the tool genuinely did.** It read the git-tracked source of the
target repo (Python AST for the deep path, regex for Jinja/JS/TS) and ran
four detector families -- codegen/template injection, tool-param
injection, auth/network posture, and secret handling -- producing the
severity- and confidence-ranked findings table above with a file:line for
each hit.

**What was expert-led (not the tool).** Separating true positives from
low-confidence heuristic noise; confirming a finding is actually reachable
from an attacker-controlled input; the fix-shape and ranked fix-lane plan
below.

**What it does NOT do -- stated plainly.** No dynamic analysis, no
cross-file taint tracking (same-file heuristics only). No MCP-manifest /
`@mcp.tool()`-decorator awareness yet: it does not detect
**write-tools-on-by-default / tool-scope-creep** or
**secret-leak-via-tool-response** -- two MCP-specific hazard classes that
are NOT yet built (see the Detector-class reference below). No git-history
secret scanning (pair with `gitleaks`). No JS/TS AST parity (regex-level
only).

*(The "above"/"below" references match this text's placement in the
delivered report, D1 §5-7; in this SOW they refer to that same report.)*

---

## 3. Deliverables

| # | Deliverable | Contents |
|---|---|---|
| D1 | Client-facing report | 8-section report: exec summary in plain incident language, top-3-to-fix, findings table (file:line · severity · class · remediation · confidence), critical-evidence appendix, detector-class reference (incl. the NOT-yet-built disclosure above), Capability statement verbatim, ranked fix-lane plan. |
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
- **No cross-file taint tracking.** Reachability is a same-file heuristic,
  stated on every report.
- **No full JS/TS AST parity.** Regex-level for non-Python source.
- **No git-history secret scanning.** Pair with `gitleaks` for history;
  not rebuilt here.
- **No write-tools-on-by-default / secret-leak-via-tool-response
  detection.** Not yet built -- see §2. If this is your primary concern,
  say so; a manual review covers it today, this scanner does not.
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
