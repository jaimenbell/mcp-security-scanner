---
title: "MCP Security Scanner -- one-pager"
type: sales-kit
audience: client-facing (send as-is or paraphrase on a call)
version: 2026-07-16
source: "README.md, PRODUCT.md, mcp_scanner/client_report.py"
tags: [mcp-security-scanner, sales-kit, one-pager]
---

# MCP Security Scanner -- one-pager

**Who this is for:** anyone building or shipping a Model Context Protocol
(MCP) server -- an agent-tool backend, a codegen tool, anything an LLM
calls. If you don't run an MCP server, this isn't for you yet.

## The wedge, in one proof

Most MCP-security vendors ask you to trust a sales deck. This tool ships
receipts instead: it runs against **six real, in-production MCP servers I
operate**, reproducibly, via `--self-audit`. It flags the one server an
independent manual audit found vulnerable (a codegen-injection class in
`mcp-factory` -- untrusted input rendered through Jinja with autoescape
off) and gives the other five a clean bill. Anyone can clone the repo,
point it at their own fleet, and reproduce the same table. That's not a
claim -- it's `tests/test_self_audit.py`.

## What it actually checks today

Six detector families, each grounded in a real finding from a fleet-wide
audit of production MCP servers:

| # | Class | Detects |
|---|---|---|
| 1 | Codegen / template injection | Jinja `autoescape` off in a code-generating tool; hand-rolled escaping instead of a real serializer. |
| 2 | Tool-param injection | `subprocess(shell=True)`, `os.system`, non-constant `eval`/`exec`, `pickle.load`, unsafe `yaml.load`, SSRF, path traversal. |
| 3 | Auth / network posture | Bind `0.0.0.0` (+debug escalation), mutating routes with no auth dependency, no rate limiter. |
| 4 | Secret handling | Tracked `.env`/`.pem`/`.key` files, hardcoded secret-shaped literals, secrets passed to log/print. |
| 5 | Write-tools-on-by-default / tool-scope-creep (added 2026-07-19) | A mutating `@mcp.tool()`-registered tool with no visible permission gate. |
| 6 | Secret-leak-via-tool-response (added 2026-07-19) | A tool's `return` value leaking a credential back through the protocol to the calling LLM. |

Every finding carries a severity (P0 critical -> P3 hardening nit), a
confidence (high/medium/low), a `file:line`, and a concrete fix.

## Honest capability boundary -- stated plainly

The two MCP-protocol-specific hazard classes an MCP-specific pitch would
naturally lead with -- write-tools-on-by-default/tool-scope-creep and
secret-leak-via-tool-response -- **now ship** (added 2026-07-19, detectors
5 and 6 above). What's still generic-Python-appsec-only rather than
MCP-manifest-aware: no cross-file taint tracking, no `server.json`/tool-schema
parsing to confirm reachability. (See `PRODUCT.md` in the repo for the
full remaining-gap list.)

## Packages

| Tier | Shape | Price |
|---|---|---|
| **One-shot audit** | Point-in-time scan of your MCP server + a hand-reviewed 8-section report (exec summary, top-3-to-fix, findings table, evidence appendix for every critical, honest scope statement, ranked fix-lane plan). | $250-750 fixed |
| **CI-gate watch** | The scanner wired into your CI (`--fail-on P1`) so a regression can't merge silently, plus a monthly re-scan digest. | $99-149/mo |
| **Fix-it add-on** | Scan -> prioritized fixes -> re-verify. Natural bolt-on if you're already having your MCP server built or reviewed. | scoped per finding |

## Scope rails

**Explicitly NOT included:** dynamic/runtime analysis, cross-file taint
tracking (same-file heuristics only), full JS/TS AST parity (regex-level),
git-history secret scanning (pair with `gitleaks`), a hosted/SaaS
dashboard (CLI + CI gate only, today), and the two undetected classes
above.

## Next step

Two ways to move: I run `mcp-scan` against your repo and send the 8-section
report, or you clone the repo and run `--self-audit` against your own
fleet first to see the tool prove itself before trusting it on your code.
Either way, nothing in your stack is modified, deleted, or executed --
static read-only analysis only.
