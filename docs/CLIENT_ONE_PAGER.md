---
title: "MCP Security Scanner -- one-pager"
type: sales-kit
audience: client-facing (send as-is or paraphrase on a call)
version: 2026-07-23
source: "README.md, PRODUCT.md, mcp_scanner/client_report.py"
tags: [mcp-security-scanner, sales-kit, one-pager]
---

# MCP Security Scanner -- one-pager

**Who this is for:** anyone building or shipping a Model Context Protocol
(MCP) server -- an agent-tool backend, a codegen tool, anything an LLM
calls. If you don't run an MCP server, this isn't for you yet.

## The wedge, in one proof

Most MCP-security vendors ask you to trust a sales deck. This tool ships
receipts instead: it runs against **eight real, in-production MCP servers I
operate**, reproducibly, via `--self-audit`. Six get a clean bill. Two
(`github-mcp`, `discord-mcp`) show a low-confidence P1 -- the scanner
honestly flagging their own obviously-fake test-fixture tokens rather than
hiding them, exactly the "demote confidence, never suppress visibility"
rule the tool is built on. (A codegen-injection class an earlier manual
audit found in `mcp-factory` was fixed upstream and the fleet now scans
clean there too -- the detection class itself stays proven against a
regression fixture.) Anyone can clone the repo, point it at their own
fleet, and reproduce the same table. That's not a claim -- it's
`tests/test_self_audit.py`.

## What it actually checks today

Seven detector families. The first six are grounded in a real finding from
a fleet-wide audit of production MCP servers; the seventh (added
2026-07-21) covers scheduled jobs, wrappers, and IaC/CI files:

| # | Class | Detects |
|---|---|---|
| 1 | Codegen / template injection | Jinja `autoescape` off in a code-generating tool; hand-rolled escaping instead of a real serializer. |
| 2 | Tool-param injection | `subprocess(shell=True)`, `os.system`, non-constant `eval`/`exec`, `pickle.load`, unsafe `yaml.load`, SSRF, path traversal. |
| 3 | Auth / network posture | Bind `0.0.0.0` (+debug escalation), mutating routes with no auth dependency, no rate limiter. |
| 4 | Secret handling | Tracked `.env`/`.pem`/`.key` files, hardcoded secret-shaped literals, secrets passed to log/print. |
| 5 | Write-tools-on-by-default / tool-scope-creep (added 2026-07-19) | A mutating `@mcp.tool()`-registered tool with no visible permission gate. |
| 6 | Secret-leak-via-tool-response (added 2026-07-19) | A tool's `return` value leaking a credential back through the protocol to the calling LLM. |
| 7 | Job hazards (added 2026-07-21) | Over-broad credential/ACL scope, an unconfirmed destructive call, or unverified-success reporting in cron/systemd/GitHub Actions/PowerShell/bash/batch job and deploy files. |

Every finding carries a severity (P0 critical -> P3 hardening nit), a
confidence (high/medium/low), a `file:line`, and a concrete fix.

Four of these seven families -- tool-param injection, tool-scope-creep,
secret-leak-via-tool-response, and secret handling's secret-in-log check --
also run on JS/TS source (`.js`/`.mjs`/`.ts`), via string-aware regex
heuristics rather than a JS/TS AST. Codegen-injection and auth-posture
stay Python-only by deliberate scope decision (they're inherently
Jinja- and Flask/FastAPI-decorator-shaped).

## Honest capability boundary -- stated plainly

Beyond the seven detectors, the scanner now grades every finding two more
ways. **Reachability** (built 2026-07-21): it discovers your registered
MCP tools (`@mcp.tool()`/`server.tool(...)` and any `server.json` manifest)
and walks a static call-graph to label each finding reachable from a tool,
unreachable, or unknown -- same-file exact, cross-file best-effort by
function name. **Tool-parameter taint tracking v1** (built 2026-07-21,
cross-file budget raised 2026-07-22): it seeds each tool handler's
parameters as taint sources and traces them same-file transitively and up
to **two** direct-import hops cross-file into the dangerous sinks, labelling
each finding tainted / untainted / unknown. Neither grading pass ever drops
a finding -- it only raises or lowers confidence, so the over-flag
philosophy holds throughout.

What's still out: a third taint hop and cross-repo flow, sanitizer-aware
propagation, and full JS/TS AST parity (today's JS/TS coverage is
string-aware regex heuristics with documented gaps -- see `README.md`'s
"Known JS/TS regex-heuristic gaps" section for the specifics, e.g.
optional-chaining `eval` and a `return {...secret}` spread shape). (See
`PRODUCT.md` in the repo for the full remaining-gap list.)

## Packages

| Tier | Shape | Price |
|---|---|---|
| **One-shot audit** | Point-in-time scan of your MCP server + a hand-reviewed 8-section report (exec summary, top-3-to-fix, findings table, evidence appendix for every critical, honest scope statement, ranked fix-lane plan). | $250-750 fixed |
| **CI-gate watch** | The scanner wired into your CI (`--fail-on P1`) so a regression can't merge silently, plus a monthly re-scan digest. | $99-149/mo |
| **Fix-it add-on** | Scan -> prioritized fixes -> re-verify. Natural bolt-on if you're already having your MCP server built or reviewed. | scoped per finding |

## Scope rails

**Explicitly NOT included:** dynamic/runtime analysis, taint tracking
past two cross-file import hops or across repos, sanitizer-aware taint
(a validated value is still treated as tainted, by design), full JS/TS
AST parity (today's JS/TS coverage is regex/heuristic, four of seven
detector families, with documented gaps), git-history secret scanning
(pair with `gitleaks`), and a hosted/SaaS dashboard (CLI + CI gate only,
today).

## Next step

Two ways to move: I run `mcp-scan` against your repo and send the 8-section
report, or you clone the repo and run `--self-audit` against your own
fleet first to see the tool prove itself before trusting it on your code.
Either way, nothing in your stack is modified, deleted, or executed --
static read-only analysis only.
