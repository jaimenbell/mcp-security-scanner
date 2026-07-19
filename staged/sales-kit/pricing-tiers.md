---
title: "Sales Conversation Kit -- Pricing Tiers Explainer"
type: sales-kit
audience: internal (prep before/during a sales call; can be paraphrased to a client)
version: 2026-07-16
source: "docs/CLIENT_ONE_PAGER.md, docs/SOW_TEMPLATE.md §7, PRODUCT.md"
tags: [mcp-security-scanner, sales-kit, pricing]
---

# Pricing Tiers -- How the Three Engagements Chain

Three tiers, each one optional past the first. None requires committing to
the next -- the chain is a natural sequence, not a lock-in.

---

## Tier 1 -- One-Shot Audit ("Scan") -- $250-750 fixed

**Standalone. Opens every engagement. No commitment past it.**

What's included:
- A full scan of the target repo's git-tracked source across the 6 built
  detector families (codegen injection, tool-param injection, auth/network
  posture, secret handling, write-tools-on-by-default/tool-scope-creep,
  secret-leak-via-tool-response -- the last two added 2026-07-19).
- The 8-section client report (`mcp_scanner/client_report.py`): exec
  summary, top-3-to-fix, findings table with remediation + confidence,
  critical-evidence appendix, detector-class reference (all six classes),
  Capability statement verbatim, ranked fix-lane plan.
- Raw JSON export for the client's own tooling.

Effort shape: scan + report render is near-instant tooled work; the
billable time is human triage -- reading each finding against the actual
tool code to separate a real hit from a heuristic false positive (e.g. a
variable file path in a test fixture) before it's called a finding.

**Why the band is $250-750, not a fixed number:** scope is set by repo
size and finding count, not a generic package. This band is
*intentionally lower* than a full expert-adjudicated audit (compare
reliability-retainer's $5-15k reliability audit) because this scanner
covers narrower, more automatable ground -- 6 generic-appsec/MCP-aware
detector classes with a tested false-positive floor, not a hand-built
hazard catalog with live-system evidence reproduction.

**What triggers the upsell to Tier 2:** any P0/P1 finding raises the
natural next question -- "how do I stop this from regressing." Tier 2
answers it.

---

## Tier 2 -- CI-Gate Watch -- $99-149/mo

**Optional, separately scoped. Keeps the scan running as the repo changes.**

What's included:
- The scanner wired into the client's CI via `--fail-on P1` -- a P0/P1
  regression fails the build instead of merging silently.
- A monthly re-scan digest as the MCP server evolves.

**Why this band:** it undercuts the sales-gated incumbents in this space
(Enkrypt AI, Gopher Security, mcpscan.ai, MCP Manager all sales-gate
pricing; adjacent security-SaaS comps like Prowler/JFrog sit at $99-149/mo)
-- this scanner's job here is regression prevention, not a hosted
dashboard. There is no hosted/SaaS delivery layer today; this tier is a CI
config, not a service.

**Honest note on sequencing:** this tier is priced for what exists today
-- a CLI wired into CI. It is not a continuous-monitoring dashboard; that
would need the hosted-delivery work `PRODUCT.md` already flags as not yet
built.

---

## Tier 3 -- Fix-It Add-On -- scoped per finding

**Optional. Turns the Tier-1 fix-lane plan into shipped fixes.**

What's included:
- The Tier-1 report's ranked fix-lane plan executed: each finding fixed
  and re-verified with a follow-up scan showing the finding cleared.

**Why this isn't a fixed price:** a single P1 `shell=True` fix is a
different job than a repo-wide secret-handling cleanup across a dozen
files -- the Tier-1 audit is what prices it, honestly, per client. This is
also the natural bolt-on point if the client is already having their MCP
server built or reviewed (see the objection-FAQ "upsell, not cold-lead"
note).

---

## The chain, one line each

**Audit finds and proves it (the fix-lane plan) -> CI-gate Watch stops
regressions -> Fix-It closes the found gaps.**

Every tier stands alone if that's all the client wants. Nothing here is
sold as a bundle they have to buy up front.

## What's now included that wasn't before (updated 2026-07-19)

Write-tools-on-by-default / tool-scope-creep detection and
secret-leak-via-tool-response detection **shipped 2026-07-19** and are
included in every Tier-1 scan at no extra charge (see `PRODUCT.md` and the
Capability statement in every delivered report). What's still NOT
included at any tier: cross-file taint tracking beyond a single-hop
helper check, `server.json`/tool-schema-based reachability confirmation,
git-history secret scanning, and full JS/TS AST parity.
