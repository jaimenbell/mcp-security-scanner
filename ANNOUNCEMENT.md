---
title: Announcing mcp-security-scanner
type: announcement
status: prototype
---

# mcp-security-scanner: a static security scanner for MCP servers, with a reproducible self-audit

> [!info] What this is
> A **credibility artifact**, not a product launch. This is a grep-grade static
> analysis tool that flags the vulnerability classes we've actually seen in
> production MCP servers, with an honest confidence rating on every finding.
> It is a lead-gen and expert-triage aid — a prioritized review queue for a
> human to work from — not a SaaS, not a prover, and not a substitute for a
> real security review.

## What it does

Point it at an MCP server repo. It reads the git-tracked source (Python AST
for the deep path, regex for Jinja/JS/TS) and checks for seven vulnerability
classes — the first six grounded in a real finding from a fleet-wide audit
of production MCP servers, the seventh covering the operational surface
around them:

1. **Codegen / template injection** — Jinja `autoescape` off in a
   code-generating tool, or hand-rolled string escaping instead of a real
   serializer.
2. **Tool-param injection** — `subprocess(shell=True)`, `os.system`,
   non-constant `eval`/`exec`, `pickle.load`, unsafe `yaml.load`, SSRF, path
   traversal.
3. **Auth / network posture** — binding `0.0.0.0` (worse paired with
   `debug=True`), mutating routes with no auth dependency, no rate limiter.
4. **Secret handling** — tracked `.env`/`.pem`/`.key` files, hardcoded
   secret-shaped literals, secrets passed to log/print.
5. **Write-tools-on-by-default / tool-scope-creep** (added 2026-07-19) — a
   mutating `@mcp.tool()`-registered tool with no visible permission gate.
6. **Secret-leak-via-tool-response** (added 2026-07-19) — a tool's `return`
   value leaking a credential back to the calling LLM.
7. **Job / wrapper / CI hazards** (added 2026-07-21) — scheduled jobs,
   launcher wrappers, and IaC/CI files around the server itself.

Every finding carries a severity (P0 critical -> P3 hardening nit), a
confidence (high/medium/low), a `file:line`, and a concrete fix. False
positives are allowed by design on the low-confidence tier — a "clean bill"
is severity-based (no P0/P1), and the scanner would rather show you a
LOW-confidence finding it demoted than silently hide it (that's the one-law
rule: only our own curated exact-match judgments may fully suppress; a
target's own markers can only lower confidence, never visibility).

## The self-audit: run it on the vendor's own code

The strongest trust signal we can offer in a market recently burned by faked
proof-of-work is: **check our own code, not our sales deck.** The scanner
ships with `--self-audit`, which runs it against eight real, in-production
MCP servers I operate. Anyone can clone this repo, point
`MCP_SCANNER_FLEET_ROOT` at their own fleet (or ours, if shared), and
reproduce this exact table:

```
MCP Fleet Self-Audit
============================================================
CLEAN    mcp-factory                              P0=0 P1=0 P2=0 P3=0 (50 files)
FINDINGS github-mcp                               P0=0 P1=2 P2=0 P3=0 (24 files)
CLEAN    bus-mcp                                  P0=0 P1=0 P2=0 P3=0 (20 files)
CLEAN    desktop-mcp                              P0=0 P1=0 P2=1 P3=0 (25 files)
CLEAN    rag-mcp                                  P0=0 P1=0 P2=1 P3=0 (27 files)
FINDINGS discord-mcp                              P0=0 P1=1 P2=0 P3=0 (16 files)
CLEAN    rails-mcp                                P0=0 P1=0 P2=0 P3=0 (22 files)
CLEAN    vllm-ops-mcp                             P0=0 P1=0 P2=1 P3=0 (17 files)
============================================================
2 server(s) with P0/P1 findings, 6 clean bill.
```

The history behind this table is the actual product demo. Earlier this month
the scanner flagged real P1s in `mcp-factory` (a codegen-injection class an
independent manual audit had already found) and `bus-mcp` (four write-tools
with no visible permission gate — caught by the tool-scope-creep detector
added 2026-07-19); both got fixed and are clean above. `vllm-ops-mcp` then
briefly showed three P1s that turned out to be a detector heuristic matching
a helper function's *name*, not an actual mutation path — that false-positive
class got a real fix (resolution-based sink classification, N-vote-reviewed),
which is why it now reads clean instead of over-flagged. And the two FINDINGS
rows remaining are the honesty feature working as designed: github-mcp and
discord-mcp embed obviously-fake test tokens in their own fixtures, and the
scanner now reports those as LOW-confidence P1s instead of silently hiding
them — a target's own "this is fake" markers can lower confidence, never
visibility. That's the product in one sentence: the scanner finds real
things, and it's honest about what it demotes. This is
`tests/test_self_audit.py` — a real, checkable test, not a claim, and the
table above is a live re-run (2026-07-23).

```bash
export MCP_SCANNER_FLEET_ROOT=/path/to/your/mcp/repos   # your own fleet
python -m mcp_scanner.cli --self-audit
```

## Honest scope

- **Static only.** No dynamic analysis. Reachability comes from a static
  call-graph over discovered MCP tool registrations; tool-parameter taint
  tracking follows up to two cross-file import hops (no third hop, no
  cross-repo flow, not sanitizer-aware — by design).
- **A triage aid, not a verdict.** It produces a prioritized review queue.
  A "clean bill" means these detectors found no critical/high patterns in
  this pass — not a guarantee of security.
- **Expert-in-the-loop is the product.** The scanner's job is to cut a large
  codebase down to a short list a human can actually review. Separating true
  positives from heuristic noise, and writing the fix, is the billable
  expertise.
- **Not a SaaS.** It's a CLI you run locally or wire into CI
  (`--fail-on P1`). No hosted service exists today.

346 tests total (`python -m pytest -q`) — 337 pass by default, 9 fleet
self-audit tests skip without `MCP_SCANNER_FLEET_ROOT` set. Covers matched
vuln/clean fixture pairs per detector, the self-audit proof above, the
8-section client-report renderer, and a paired regression test for every
demotion (a real secret/exec in the same shape must still flag).
(Live-reverified 2026-07-23.)
