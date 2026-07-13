---
title: MCP Server Security Scanner
type: product-readme
status: prototype
---

# mcp-security-scanner

A static security scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers. Point it at an MCP server repo; it reads the source and flags the vulnerability classes that actually show up in production MCP servers — with a severity, a `file:line`, a remediation, and an honest **confidence** on every finding.

> [!info] What this is, plainly
> This is **static analysis**, not a prover. It reads code; it does not run your server, and it does not prove any finding is remotely exploitable. It produces a prioritized review queue, not a verdict. A "clean bill" means *these detectors found no critical/high patterns* — not a security guarantee. That boundary is printed on every report on purpose.

## What it scans

Four detector families, each grounded in a real finding from a fleet-wide audit of production MCP servers:

| # | Class | Detects |
|---|---|---|
| 1 | **Codegen / template injection** | Jinja `autoescape` off in a code-*generating* tool that renders untrusted fields into generated source; hand-rolled `replace('"','\"')` escaping instead of a real serializer (the mcp-factory class). |
| 2 | **Tool-param injection** | `subprocess(shell=True)`, `os.system`, `eval`/`exec` on non-constants, `pickle.load`, `yaml.load` without `SafeLoader`, SSRF (caller-influenced fetch URL, no allowlist), path traversal (variable file path, no containment). |
| 3 | **Auth / network posture** | Bind on `0.0.0.0` (escalates when paired with `debug=True`), Werkzeug/uvicorn `debug=True`, mutating routes (POST/PUT/DELETE/PATCH) with no auth dependency, no rate limiter on a networked server. |
| 4 | **Secret handling** | Tracked `.env` / `*.pem` / `*.key` / keypair JSON, hardcoded secret literals (value-shape + secret-named assignments), secrets passed to log/print. |

Every finding carries **severity** (P0 critical → P3 hardening nit), **confidence** (high / medium / low), the offending `file:line`, and a concrete fix.

## Install / run

```bash
# from the repo root
python -m mcp_scanner.cli <path-to-mcp-server>          # markdown report
python -m mcp_scanner.cli <path> --json                 # JSON
python -m mcp_scanner.cli <path> --fail-on P1           # CI gate: exit 2 on P0/P1
python -m mcp_scanner.cli --self-audit                  # scan your own fleet's servers
```

`--self-audit` reads the directory to scan from the `MCP_SCANNER_FLEET_ROOT`
environment variable — there is no baked-in default, so this repo carries no
personal path. Set it to the directory containing the MCP server repos you
want audited:

```bash
export MCP_SCANNER_FLEET_ROOT=/path/to/your/mcp/repos    # bash
$env:MCP_SCANNER_FLEET_ROOT = "C:\path\to\your\projects"  # PowerShell
```

Without it set, `--self-audit` exits 1 with a clear error rather than
silently defaulting anywhere.

Or install the console script:

```bash
pip install -e .
mcp-scan <path-to-mcp-server>
```

The scanner reads only git-tracked source (falling back to a filtered tree walk in non-git dirs), so vendored deps, caches, and vector stores are skipped.

## The dogfood proof (`--self-audit`)

The scanner is validated against **six real, in-production MCP servers** — the strongest trust signal we can offer in a market that has been burned by simulated proof-of-work. Running `--self-audit`:

```
FINDINGS mcp-factory   P0=0 P1=1 P2=0 P3=0   <- flags the known codegen-injection class
CLEAN    github-mcp    P0=0 P1=0 P2=0 P3=0
CLEAN    bus-mcp       P0=0 P1=0 P2=0 P3=0
CLEAN    desktop-mcp   P0=0 P1=0 P2=1 P3=0   <- one P2/low heuristic note, clean bill
CLEAN    rag-mcp       P0=0 P1=0 P2=1 P3=0   <- one P2/low heuristic note, clean bill
CLEAN    discord-mcp   P0=0 P1=0 P2=0 P3=0
```

This is the acceptance test (`tests/test_self_audit.py`): it must (a) flag the mcp-factory codegen-injection class an independent manual audit found, and (b) give the audited-clean servers a clean bill (no P0/P1). It does both.

## Honest capability boundary

- **Static only.** No dynamic analysis, no taint tracking across function boundaries, no cross-file dataflow. Reachability is inferred from same-file heuristics.
- **Confidence is load-bearing.** `low` findings are "a human should glance at this," and produce false positives by design (e.g. a variable file path in a test file). They are P2/P3 and never break a clean bill.
- **Not a git-history scanner.** The secret detector reads the tracked working tree, not full history. Pair it with `gitleaks` for history.
- **Language coverage.** Deep for Python (AST-based); regex-level for Jinja templates and JS/TS.

## Tests

```bash
python -m pytest -q     # 28 tests: per-detector vuln/clean fixtures + the self-audit proof
```

The self-audit tests (7 of the 28) require `MCP_SCANNER_FLEET_ROOT` to be set
and pointed at real MCP server repos to scan; they skip cleanly if it's
unset (e.g. in a fresh clone or CI on another machine). See
[ANNOUNCEMENT.md](ANNOUNCEMENT.md) for the reproducible self-audit output.

Each detector ships a matched pair of fixtures — a vulnerable one it must catch, a clean one it must not flag — so the false-positive floor is a tested invariant, not a hope.
