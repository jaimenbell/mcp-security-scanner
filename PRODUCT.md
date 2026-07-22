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

**Done (this repo):** seven grounded detectors (the original four, plus write-tools-on-by-default/tool-scope-creep and secret-leak-via-tool-response shipped 2026-07-19, plus job-hazards shipped 2026-07-21 -- see below), AST-based Python analysis, honest confidence/severity model, client-facing markdown + JSON reports, an 8-section consulting-grade client report (`mcp_scanner/client_report.py`, `--client-report`), a sales kit (`docs/CLIENT_ONE_PAGER.md`, `docs/SOW_TEMPLATE.md`, `staged/sales-kit/pricing-tiers.md`, `staged/sales-kit/objection-faq.md`), CI gate, and a passing dogfood self-audit against the fleet's real servers. This was Phase 0 of the 2026-07-16 retainer spec; the sales-kit docs still need a pass to reflect the newest detector landing (same "update in the same wave" note pattern as the 07-19 pair).

**Phase 1 depth (2026-07-21):** the retainer pitch (`reliability-retainer/staged/SEND-NOW-2026-07-20.md`) promises static sweeps of "every scheduled job, wrapper, and IaC/CI file -- cron, systemd, GitHub Actions, your Railway/deploy configs" for "a token or policy scoped wider than the job it serves, a destructive call with no confirm-before-destroy gate, a job that can report 'done' without verifying what it touched." Before this wave the scanner didn't even read `.yml`/`.ps1`/`.sh`/`.bat`/`.service` files -- the pitch wasn't literally true yet. `mcp_scanner/detectors/job_hazards.py` (detector 7, `job-hazards`) plus a `scanner.py` file-type extension closes that gap: over-broad credential/ACL scope, unconfirmed destructive calls, and unverified-success patterns, each with file:line + severity + confidence. The ranked client-deliverable report generator (`client_report.py` / `--client-report`, 8-section, severity-ranked, file:line per finding) already existed from Phase 0 and needed no rebuild -- it now also renders job-hazards findings.

**Still needed before it's a sellable SaaS:**

1. **Cross-file dataflow / taint** — current reachability is same-file heuristic; a real product wants tool-arg → sink tracing to lift confidence and cut P2/low noise.
2. **Deeper JS/TS coverage** — regex-level today; AST-parity with the Python path.
3. **MCP-manifest awareness** — parse `server.json` / tool schemas to map which detected sinks are actually reachable from a declared tool parameter (the single biggest precision win).
4. **Hosted delivery** — a thin web/CI surface for the continuous tier; today it is a CLI.
5. **Git-history secret scanning** — fold in gitleaks so the secret detector covers history, not just the working tree.
6. **A curated rule set + suppression file** — so clients can baseline known-accepted findings.

**Honest verdict:** this is a credible *prototype* and a genuine differentiator (the self-audit proof is real and reproducible), but it is a lead-gen + expert-triage tool today, not yet a standalone automated SaaS. The gap to "product" is precision (items 1–3) and delivery (item 4) — a scoped build, not a research problem.
