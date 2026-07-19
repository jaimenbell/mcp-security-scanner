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
for the deep path, regex for Jinja/JS/TS) and checks for six vulnerability
classes, each grounded in a real finding from a fleet-wide audit of
production MCP servers:

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

Every finding carries a severity (P0 critical -> P3 hardening nit), a
confidence (high/medium/low), a `file:line`, and a concrete fix. Findings
below high confidence never break a "clean bill" — false positives are
allowed by design on the low tier, and are excluded from the pass/fail
signal on purpose.

## The self-audit: run it on the vendor's own code

The strongest trust signal we can offer in a market recently burned by faked
proof-of-work is: **check our own code, not our sales deck.** The scanner
ships with `--self-audit`, which runs it against six real, in-production MCP
servers I operate. Anyone can clone this repo, point `MCP_SCANNER_FLEET_ROOT`
at their own six repos (or ours, if shared), and reproduce this exact table:

```
MCP Fleet Self-Audit
============================================================
FINDINGS mcp-factory                              P0=0 P1=1 P2=0 P3=0 (41 files)
CLEAN    github-mcp                               P0=0 P1=0 P2=0 P3=0 (20 files)
CLEAN    bus-mcp                                  P0=0 P1=0 P2=0 P3=0 (15 files)
CLEAN    desktop-mcp                              P0=0 P1=0 P2=1 P3=0 (21 files)
CLEAN    rag-mcp                                  P0=0 P1=0 P2=1 P3=0 (22 files)
CLEAN    discord-mcp                              P0=0 P1=0 P2=0 P3=0 (15 files)
============================================================
1 server(s) with P0/P1 findings, 5 clean bill.
```

That is: it flags the one server (`mcp-factory`) that an independent manual
audit found vulnerable (a codegen-injection class), and gives the other five
a clean bill — no P0/P1 findings, and the two P2 hits are low-confidence
heuristic notes that never fail the bill. This is `tests/test_self_audit.py`
— it's a real, checkable test, not a claim.

```bash
export MCP_SCANNER_FLEET_ROOT=/path/to/your/mcp/repos   # your own fleet
python -m mcp_scanner.cli --self-audit
```

## Honest scope

- **Static only.** No dynamic analysis, no cross-file taint tracking.
  Reachability is inferred from same-file heuristics.
- **A triage aid, not a verdict.** It produces a prioritized review queue.
  A "clean bill" means these detectors found no critical/high patterns in
  this pass — not a guarantee of security.
- **Expert-in-the-loop is the product.** The scanner's job is to cut a large
  codebase down to a short list a human can actually review; separating true
  positives from heuristic noise, and writing the fix, is the billable
  expertise.
- **Not a SaaS.** It's a CLI you run locally or wire into CI
  (`--fail-on P1`). No hosted service exists today.

55 tests (`python -m pytest -q`; 48 pass by default, 7 self-audit tests
skip without `MCP_SCANNER_FLEET_ROOT` set): matched vuln/clean fixture
pairs per detector, the self-audit proof above, and the 8-section
client-report renderer.
