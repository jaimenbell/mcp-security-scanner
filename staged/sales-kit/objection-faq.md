---
title: "Sales Conversation Kit -- Objection FAQ"
type: sales-kit
audience: internal (prep before/during a sales call or reply thread)
version: 2026-07-16
source: "README.md, PRODUCT.md, ANNOUNCEMENT.md, docs/CLIENT_ONE_PAGER.md, docs/SOW_TEMPLATE.md"
tags: [mcp-security-scanner, sales-kit, objections, faq]
---

# Objection FAQ -- MCP Security Scanner

Every answer below is grounded in what the scanner actually does today.
Nothing here should be said if it isn't true yet -- if capability changes
(the two undetected classes ship), update this file in the same wave.

---

## "Do you detect write-tools-on-by-default or secret-leak-via-tool-response?"

**Not yet. Say this first, before anything else, if it's asked.** These are
exactly the MCP-specific hazard classes a security pitch would naturally
lead with, and this scanner does not check for them today. The 4 built
detectors are generic-Python-appsec checks (codegen injection, tool-param
injection, auth/network posture, secret handling) -- they apply to an MCP
server because it's a Python process, but none of them parse
`@mcp.tool()`/`FastMCP` registrations or reason about what a tool's
`return` value sends back to the calling LLM. If either of these is the
client's actual concern, a manual review covers it today, not this
scanner -- say so plainly rather than implying otherwise.

## "Isn't this just grep / a regex scanner?"

Two of the four detectors are AST-based (Python), and the tool-param and
auth-posture checks pattern-match real dangerous sinks (`shell=True`,
`eval` on non-constants, `pickle.load`, unsafe `yaml.load`), not bare text
search. That said: it *is* static, heuristic, same-file-only, and says so
on every report -- no dynamic analysis, no cross-file taint. The band is
priced lower than a full expert-adjudicated audit (see pricing-tiers.md)
specifically because it covers narrower, more automatable ground.

## "Why not just run Semgrep / Bandit?"

Those are general-purpose SAST tools with broad rule sets; this scanner is
narrower and MCP-context-scoped -- the 4 classes are each grounded in a
real finding from a fleet-wide audit of production MCP servers, not a
generic ruleset. It's complementary, not a replacement: pairing this with
a general SAST tool and `gitleaks` for git-history secrets is the honest
answer, and the report says so (see the Detector-class reference section).

## "Will this touch or break our production systems?"

No. Static-only: the scanner reads git-tracked source and never runs,
deploys, or executes anything in the target repo. There is no dynamic
analysis and no live network calls against the target.

## "What if you find nothing?"

Already demonstrated, honestly: `--self-audit` gives 5 of the operator's
own 6 production MCP servers a clean bill (no P0/P1) and flags the one
with a known issue. If your repo is genuinely clean against these 4
detector classes, the report says so plainly -- it does not manufacture a
finding to justify the fee. A clean bill also isn't a guarantee: the
report's Scope & method section states what static analysis can and
cannot prove.

## "Why you, and not a funded competitor (Enkrypt AI, Gopher Security, mcpscan.ai, MCP Manager)?"

Those vendors all sales-gate their pricing -- you talk to sales before you
see a number or a sample report. This scanner is transparent by design:
open pricing bands, an open-source repo, and a reproducible self-audit
against six real, in-production MCP servers anyone can check themselves.
It's also honest about its gaps in a market that tends not to be --
stating plainly what it does not detect (see above) rather than implying
full coverage.

## "$250-750 for a scan?"

That reflects the actual scope: a tooled scan plus human triage separating
real findings from heuristic noise, delivered as an 8-section report with
a file:line and a concrete fix for every finding. It's priced below a full
expert-adjudicated audit on purpose -- this is 4 automatable detector
classes with a tested false-positive floor (every detector ships a
matched vuln/clean fixture pair), not a hand-built hazard catalog with
live-evidence reproduction. If the finding count or repo size pushes past
a quick pass, the fee moves within the band, stated up front.
