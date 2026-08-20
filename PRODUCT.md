---
title: "MCP Security Scanning — Service Offering"
type: product-sketch
status: prototype-stage
grounded_in: "2026-07-12 internal revenue-streams discovery"
---

> [!danger] WITHDRAWN OFFER - DO NOT SEND, DO NOT QUOTE (withdrawn 2026-07-29; banner added 2026-08-20)
> The paid audit tier this document sells ($250 / $450 / $750) was **withdrawn on 2026-07-29**,
> after the scanner was measured **blind against pre-frozen ground truth** and returned
> **0 true positives across 58 findings, and pooled recall of 0 of 69.**
>
> A clean result from a detector with 0/69 recall provably carries no information - silence is what
> it returns on vulnerable code too. So the self-audit table, wherever this file leans on it, is not
> evidence of efficacy and must not be cited as a trust signal.
>
> **The withdrawal did not reach every rail.** The tier was **relisted on Gumroad 2026-08-13** and
> was still selling on **2026-08-20**; 24 outreach emails went out 2026-07-23 to 08-17, four of them
> quoting these prices. A withdrawal is not finished until every surface that can take money for it
> is closed.
>
> This file is kept as a record of what was offered, **not as a sellable artifact**. Do not fill it
> in, do not send it, do not reuse its pricing. Outreach is halted.


# MCP Security Scanning — service sketch

> Revenue stream #2 from the 2026-07-12 revenue-streams discovery. This document sketches the offer; the sibling `README.md` is the working prototype it is built on.

## The wedge (why this exists)

The discovery research found a genuine, narrow gap:

- **Nobody in the MCP-security space publishes transparent, self-serve, continuous-scanning pricing** — not even the funded players. Enkrypt AI ($2.35M seed, ran the widely-cited "33% of 1,000 MCP servers had critical vulns" study), Gopher Security, mcpscan.ai, and MCP Manager **all sales-gate their pricing.** Adjacent security-SaaS comps (Prowler, JFrog) sit in a **$99–149/mo** band a transparent entrant can match or undercut.
- The buyer market is real and recently **burned by fake proof-of-work** (the Oura-Ring fake-GitHub-persona supply-chain incident). In that climate, a vendor who can *show* real, checkable, working MCP servers is a differentiator, not a marketing line.

## ~~The unfair advantage: the 6-server trust signal~~ — REFUTED 2026-07-29, DO NOT USE

> **This section was the pitch's centrepiece and it does not survive measurement. Kept, struck
> through, as the record — not as copy.**
>
> On 2026-07-29 the scanner was measured **blind against pre-frozen ground truth** on five pinned
> third-party servers: **0 true positives across 58 findings, and pooled recall 0 of 69.** The paid
> audit tier was withdrawn the same day.
>
> That result refutes the claim below directly. A self-audit cannot be a trust signal, because a
> clean result from a detector with 0/69 recall **provably carries no information** — silence is
> what it returns on vulnerable code too. The permitted framing is the measurement story itself
> ("I built it, measured it blind, it scored 0/69, and I pulled the tier"), never the self-audit
> table as evidence of efficacy.
>
> ⚠ The withdrawal was **not** propagated to every rail: the tier was relisted on Gumroad
> 2026-08-13 and was still selling on 2026-08-20. A withdrawal is not finished until every surface
> that can take money for it is closed.

~~The operator runs **six real, in-production MCP servers** (mcp-factory, github-mcp, bus-mcp, desktop-mcp, rag-mcp, discord-mcp). This scanner's `--self-audit` runs against all six and is checkable by any prospect:~~

- ~~It **flags** the one server an independent manual audit found vulnerable (mcp-factory's codegen-injection class).~~
- ~~It gives the **other five a clean bill.**~~

~~That is a live, reproducible demonstration that the tool finds real bugs *and* doesn't cry wolf — on the vendor's own code. Most competitors ask you to trust a sales deck; this ships the receipts.~~

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

**Phase 2 precision (2026-07-21):** manifest-aware **reachability grading** shipped (`mcp_scanner/reachability.py` + `mcp_scanner/tool_registry.py`). A post-detector pass discovers the registered MCP tools (`@mcp.tool()`/`server.tool(...)` decorators and any `server.json` manifest — the tool-scope-creep detector's decorator parser was extracted into the shared `tool_registry` module rather than duplicated) and walks a static call-graph, labelling every finding `reachable` / `unreachable-by-tools` / `unknown` and nudging confidence up/down accordingly (never dropping a finding). Same-file call-graph is exact; cross-file is best-effort by function name. This is item 3 below, delivered with stated limits — it labels reachability, not the individual tainted value (taint tracking v1, Phase 3 below).

**Phase 3 precision (2026-07-21):** tool-parameter **taint tracking v1** shipped (`mcp_scanner/taint.py`). A second post-detector pass seeds every registered tool handler's parameters as taint sources and propagates them through assignments, f-strings/concat/`.format()`, containers, and same-repo function calls into the param-injection sinks, labelling every such finding `tainted` / `untainted` / `unknown` and nudging confidence up/down (never dropping — an `untainted` sink is still reported, lower-confidence). Same-file dataflow is transitive; cross-file follows **one direct-import hop**. Stated limits (honest): no second hop / cross-repo flow, not sanitizer-aware, no dynamic dispatch (`getattr`/`*args`/`**kwargs`) or decorator-transform tracking. This delivers item 1 below as a v1 with a documented boundary.

**Phase 4 (2026-07-22):** JS/TS detector parity + a deeper taint hop, both regex/heuristic-based (see `README.md`'s "Language coverage" bullet for the full breakdown). Five of the six detector families that previously only ran on Python source (param-injection, tool-scope-creep, secret-leak-via-tool-response, secret-handling's secret-in-log check, and — added 2026-07-30 — auth-posture's network-bind check only, not its `debug=True` or mutating-route checks, which stay deliberately Python-only) now fire on `.js`/`.mjs`/`.ts` too, via shared line-based regex helpers (`mcp_scanner/js_util.py`) -- there is still no JS/TS AST in this scanner, so this is parity of *coverage*, not of *precision* (JS/TS findings stay reachability-`unknown`; a JS tool's "body" is approximated by a capped line window, not a real function scope). Cross-file taint's hop budget went from one to two (`mcp_scanner/taint.py`).

**Still needed before it's a sellable SaaS:**

1. **Deeper / cross-repo taint** — taint tracking now traces a tool parameter same-file transitively and up to two import hops cross-file (raised from one, Phase 4). Still open: a third hop and beyond, cross-repo flow, and sanitizer-aware propagation (today a validated value is still treated as tainted, by design) — further precision to cut P2/low noise.
2. **JS/TS AST parity + the remaining two families** — Phase 4 closed the coverage gap for param-injection, tool-scope-creep, secret-leak-via-tool-response, and secret-handling's log check, but it's still regex/line-based (no real JS/TS parser), and codegen-injection (inherently Python-Jinja) and auth-posture (inherently Flask/FastAPI-decorator-shaped) were deliberately left Python-only -- an Express/Fastify auth-posture equivalent is new detector logic, not JS parity of the existing one. JS/TS findings are still labelled reachability-`unknown` (no JS/TS AST for the call-graph either). A 2026-07-22 adversarial review (two independent refuters) hardened seven real regex-robustness bugs in the JS/TS pass (comment/string-literal-aware matching, `node:` import prefix, destructure-aliased sinks, compressed one-line object-literal returns, a word-boundary guard) -- see `README.md`'s "Known JS/TS regex-heuristic gaps" bullet for what's left honestly undone (optional-chaining eval, spread-of-secret-variable returns, `.jsx`/`.tsx`/`.cjs` uncollected, a comment-blind phantom-tool over-flag, a cosmetic window-size docstring nit) rather than silently missed.
3. ~~**MCP-manifest awareness**~~ — **DONE (2026-07-21)**: `server.json` + `@mcp.tool()`/`server.tool(...)` discovery feeds both the reachability grader and the taint pass (Phase 3), mapping which findings are reachable from — and fed tainted data by — a registered tool. Deeper tool-parameter-schema → sink tracing folds into item 1.
4. **Hosted delivery** — a thin web/CI surface for the continuous tier; today it is a CLI.
5. **Git-history secret scanning** — fold in gitleaks so the secret detector covers history, not just the working tree.
6. **A curated rule set + suppression file** — so clients can baseline known-accepted findings.

**Honest verdict — REWRITTEN 2026-08-20; the original is struck through below.** Measured blind
against pre-frozen ground truth on 2026-07-29, this scanner returned **0 true positives across 58
findings and pooled recall of 0 of 69.** It is not a credible prototype pending polish, and the gap
to "product" is **not** precision-and-delivery — it is that the detectors did not find the seeded
vulnerabilities at all. Treat everything below as a design sketch whose central premise was
falsified, not as a roadmap. The one thing here that survived measurement is the honesty doctrine
itself: it is what produced the blind test, and the blind test is what killed the pitch.

~~**Honest verdict:** this is a credible *prototype* and a genuine differentiator (the self-audit proof is real and reproducible), but it is a lead-gen + expert-triage tool today, not yet a standalone automated SaaS. The gap to "product" is precision (items 1–3) and delivery (item 4) — a scoped build, not a research problem.~~
