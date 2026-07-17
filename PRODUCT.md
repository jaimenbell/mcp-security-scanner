---
title: "MCP Security Scanning — Service Offering"
type: product-sketch
status: prototype-stage
grounded_in: "[[2026-07-12 Discovery — New Revenue Streams (Fable)]]"
---

# MCP Security Scanning — service sketch

> Revenue stream #2 from the 2026-07-12 revenue-streams discovery. This document sketches the offer; the sibling `README.md` is the working prototype it is built on.

## The wedge (why this exists)

The discovery research found a genuine, narrow gap:

- **Nobody in the MCP-security space publishes transparent, self-serve, continuous-scanning pricing** — not even the funded players. Enkrypt AI ($2.35M seed, ran the widely-cited "33% of 1,000 MCP servers had critical vulns" study), Gopher Security, mcpscan.ai, and MCP Manager **all sales-gate their pricing.** Adjacent security-SaaS comps (Prowler, JFrog) sit in a **$99–149/mo** band a transparent entrant can match or undercut.
- The buyer market is real and recently **burned by fake proof-of-work** (the Oura-Ring fake-GitHub-persona supply-chain incident). In that climate, a vendor who can *show* real, checkable, working MCP servers is a differentiator, not a marketing line.

## The unfair advantage: the 6-server trust signal

The operator runs **six real, in-production MCP servers** (mcp-factory, github-mcp, bus-mcp, desktop-mcp, rag-mcp, discord-mcp). This scanner's `--self-audit` runs against all six and is checkable by any prospect:

- It **flags** the one server an independent manual audit found vulnerable (mcp-factory's codegen-injection class).
- It gives the **other five a clean bill.**

That is a live, reproducible demonstration that the tool finds real bugs *and* doesn't cry wolf — on the vendor's own code. Most competitors ask you to trust a sales deck; this ships the receipts.

## What's honest about the pitch (and why that sells here)

The report's framing is deliberately in the reliability-retainer's voice: **no fear-selling, an explicit capability boundary on every report, a confidence score on every finding.** In a market full of scanners that inflate severity to justify a renewal, "here is exactly what static analysis can and cannot tell you" is the differentiator. The same honesty doctrine that let the operator publicly kill their own trading edge ("it was 3-day market beta, not alpha") is the brand here.

## Offer shapes (candidates, not committed pricing)

| Tier | Shape | Rough band |
|---|---|---|
| **One-shot audit** | Point-in-time scan of a client's MCP server + a hand-reviewed report separating true-positives from heuristic noise, with fixes. | $250–750 fixed |
| **Continuous scan** | Scanner wired into the client's CI (`--fail-on P1`) + a monthly re-scan digest as the MCP evolves. | $99–149/mo (undercut the sales-gated incumbents) |
| **Fix-it retainer** | Scan → prioritized fixes → re-verify. Natural bolt-on to the reliability-retainer. | Retainer add-on |

The scanner's job is **lead-gen and triage**, not the whole deliverable: static analysis surfaces the queue; a human separates signal from the P2/low heuristics and writes the fix. That human-in-the-loop step is the billable expertise and the honesty guarantee.

## Sequencing (from the discovery note)

This is **ranked #2** of the new angles and explicitly **sequenced *after* the reliability-retainer's first close** — it reuses that engagement's audit tooling and borrows its first testimonial for credibility. It is **not** a competing lane for the already-fully-allocated weekly outreach hours. This prototype exists so that when the retainer closes, the build is already done.

## Prototype status → what a real product still needs

**Done (this repo):** four grounded detectors, AST-based Python analysis, honest confidence/severity model, client-facing markdown + JSON reports, an 8-section consulting-grade client report (`mcp_scanner/client_report.py`, `--client-report`), a sales kit (`docs/CLIENT_ONE_PAGER.md`, `docs/SOW_TEMPLATE.md`, `staged/sales-kit/pricing-tiers.md`, `staged/sales-kit/objection-faq.md`), CI gate, and a passing dogfood self-audit against six real servers. This is Phase 0 of `mcp-security-scanner-retainer-spec-2026-07-16.md` (report upgrade + sales-kit clone, deliberately NOT the 2 new detectors below -- gated on a real demand signal first, per the spec's own dead-but-GREEN doctrine warning).

**Still needed before it's a sellable SaaS:**

1. **Cross-file dataflow / taint** — current reachability is same-file heuristic; a real product wants tool-arg → sink tracing to lift confidence and cut P2/low noise.
2. **Deeper JS/TS coverage** — regex-level today; AST-parity with the Python path.
3. **MCP-manifest awareness** — parse `server.json` / tool schemas to map which detected sinks are actually reachable from a declared tool parameter (the single biggest precision win).
4. **Hosted delivery** — a thin web/CI surface for the continuous tier; today it is a CLI.
5. **Git-history secret scanning** — fold in gitleaks so the secret detector covers history, not just the working tree.
6. **A curated rule set + suppression file** — so clients can baseline known-accepted findings.

**Honest verdict:** this is a credible *prototype* and a genuine differentiator (the self-audit proof is real and reproducible), but it is a lead-gen + expert-triage tool today, not yet a standalone automated SaaS. The gap to "product" is precision (items 1–3) and delivery (item 4) — a scoped build, not a research problem.
