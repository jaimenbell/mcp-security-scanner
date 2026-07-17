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

Four detector families, each grounded in a real finding from a fleet-wide
audit of production MCP servers:

| # | Class | Detects |
|---|---|---|
| 1 | Codegen / template injection | Jinja `autoescape` off in a code-generating tool; hand-rolled escaping instead of a real serializer. |
| 2 | Tool-param injection | `subprocess(shell=True)`, `os.system`, non-constant `eval`/`exec`, `pickle.load`, unsafe `yaml.load`, SSRF, path traversal. |
| 3 | Auth / network posture | Bind `0.0.0.0` (+debug escalation), mutating routes with no auth dependency, no rate limiter. |
| 4 | Secret handling | Tracked `.env`/`.pem`/`.key` files, hardcoded secret-shaped literals, secrets passed to log/print. |

Every finding carries a severity (P0 critical -> P3 hardening nit), a
confidence (high/medium/low), a `file:line`, and a concrete fix.

## What it does NOT check yet -- stated plainly

These 4 detectors are generic-Python-appsec checks; they apply to an MCP
server because it's a Python process, but none of them are MCP-protocol-
aware. Two hazard classes an MCP-specific pitch would naturally lead with
are **not yet built**:

- **Write-tools-on-by-default / tool-scope-creep** -- whether a mutating
  `@mcp.tool()`-registered tool has any visible permission gate.
- **Secret-leak-via-tool-response** -- whether a tool's `return` value
  leaks a credential back through the protocol to the calling LLM.

If your main worry is one of these two, say so up front -- the honest
answer today is that a manual review, not this scanner, is what covers it.
(Both are scoped, not hand-waved -- see `PRODUCT.md` in the repo.)

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
