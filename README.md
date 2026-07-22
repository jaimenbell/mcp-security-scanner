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

Seven detector families. The first six are grounded in a real finding from a fleet-wide audit of production MCP servers; the seventh (added 2026-07-21) covers scheduled jobs, wrappers, and IaC/CI files — cron, systemd, GitHub Actions, PowerShell/bash/batch deploy scripts:

| # | Class | Detects |
|---|---|---|
| 1 | **Codegen / template injection** | Jinja `autoescape` off in a code-*generating* tool that renders untrusted fields into generated source; hand-rolled `replace('"','\"')` escaping instead of a real serializer (the mcp-factory class). |
| 2 | **Tool-param injection** | `subprocess(shell=True)`, `os.system`, `eval`/`exec` on non-constants, `pickle.load`, `yaml.load` without `SafeLoader`, SSRF (caller-influenced fetch URL, no allowlist), path traversal (variable file path, no containment). |
| 3 | **Auth / network posture** | Bind on `0.0.0.0` (escalates when paired with `debug=True`), Werkzeug/uvicorn `debug=True`, mutating routes (POST/PUT/DELETE/PATCH) with no auth dependency, no rate limiter on a networked server. |
| 4 | **Secret handling** | Tracked `.env` / `*.pem` / `*.key` / keypair JSON, hardcoded secret literals (value-shape + secret-named assignments), secrets passed to log/print. |
| 5 | **Write-tools-on-by-default / tool-scope-creep** (added 2026-07-19) | A mutating `@mcp.tool()`/`@server.tool()`-registered tool (name/verb or dangerous-sink-body heuristic, one hop through a delegated helper) with no visible gate -- decorator, env-flag opt-in, or permission check. |
| 6 | **Secret-leak-via-tool-response** (added 2026-07-19) | An `@mcp.tool()`/`@server.tool()` function whose `return` expression hands back `os.environ`, a whole config/settings object, or a secret-named/secret-shaped value to the calling LLM. |
| 7 | **Job hazards** (added 2026-07-21) | Scans `.yml`/`.yaml`/`.ps1`/`.sh`/`.bash`/`.bat`/`.cmd`/`.service`/`.timer` files for: over-broad credential/ACL scope (`permissions: write-all`, `icacls ... Everyone:F`, `chmod 777`, IAM `Action`/`Resource` wildcard pairs); a destructive call (`rm -rf`, `Remove-Item -Recurse -Force`, `terraform destroy`, `kubectl delete`, `git push --force`/`reset --hard`, `DROP TABLE`, `docker system prune`/`volume rm`, `schtasks /delete`, `aws s3 rm --recursive`) with no confirm-before-destroy gate (escalates to P0 when `-Confirm:$false` actively disables the built-in prompt); and success-reported-without-verification (`|| true`, a bare `; exit 0`, `continue-on-error: true`, an empty PowerShell `catch {}`). |

Every finding carries **severity** (P0 critical → P3 hardening nit), **confidence** (high / medium / low), the offending `file:line`, and a concrete fix.

## Install / run

```bash
# from the repo root
python -m mcp_scanner.cli <path-to-mcp-server>          # markdown report
python -m mcp_scanner.cli <path> --json                 # JSON
python -m mcp_scanner.cli <path> --client-report --client-name "Acme"  # 8-section client report
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

- **Manifest-aware reachability (built 2026-07-21).** After the detectors run, the scanner discovers the registered MCP tools (`@mcp.tool()` / `server.tool(...)` registrations and any `server.json` manifest) and walks a static call-graph to label every finding **reachable** (inside a tool handler or a function transitively called from one), **unreachable-by-tools** (no call path from any registered tool), or **unknown**. `reachable` raises a finding's confidence; `unreachable` lowers it; a finding is **never dropped** on this basis (the over-flag philosophy stands). Stated limits: the same-file call-graph is exact; cross-file is best-effort by function name (not a resolved import graph); module-level code, non-Python (JS/TS/YAML/shell) findings, and repos with no discoverable tools are labelled `unknown` rather than guessed. It labels *reachability*; the separate taint pass (below) tracks the individual tainted value.
- **Tool-parameter taint tracking v1 (built 2026-07-21; cross-file budget raised 2026-07-22).** A second post-detector pass seeds every registered tool handler's parameters as taint **sources** and propagates them through assignments, f-strings/concat/`.format()`, common containers, and same-repo function calls into the param-injection **sinks** (subprocess/`os.system`/`eval`/`exec`/`pickle`/`yaml.load`/HTTP-fetch/`open`). Each such finding is labelled **tainted** (a tool parameter provably reaches the sink), **untainted** (the sink is in tool-reachable code but fed a constant / other source), or **unknown**. `tainted` raises confidence; `untainted` lowers it; a finding is **never dropped** (the over-flag philosophy stands — an `untainted` sink is still reported, just lower-confidence). Stated limits, honestly: same-file dataflow is transitive, and cross-file follows **up to two direct-import hops** (no third hop, no cross-repo flow); it is **not sanitizer-aware** (a validated/escaped value is still treated as tainted, by design); and it does not model dynamic dispatch (`getattr` / `*args` / `**kwargs` re-binding), decorator transforms, module-level code, or non-Python surfaces — all labelled `unknown` rather than guessed. Deeper (3+ hop) and cross-repo taint remain out of scope.
- **Static only.** No dynamic analysis. Reachability and taint are inferred from the static call-graph above, not observed at runtime.
- **Confidence is load-bearing.** `low` findings are "a human should glance at this," and produce false positives by design (e.g. a variable file path in a test file). They are P2/P3 and never break a clean bill.
- **Not a git-history scanner.** The secret detector reads the tracked working tree, not full history. Pair it with `gitleaks` for history.
- **Language coverage (updated 2026-07-22).** Deep for Python (AST-based). JS/TS has no AST path in this scanner -- it is line-based regex (shared helpers in `mcp_scanner/js_util.py`), the same approach `job_hazards.py` already used for its non-Python file types. Four detector families now have JS/TS parity on this regex basis: **param-injection** (exec/execSync always-shell, spawn/execFile with `shell:true`, `eval()`/`new Function()`, `yaml.load` without a safe schema, fetch/axios/http(s).get SSRF, fs read/write path-traversal), **tool-scope-creep** (mutating `server.tool(...)` registrations with no gate, via a capped line-window heuristic standing in for a real function-body scope), **secret-leak-via-tool-response** (`process.env`/whole-config/secret-named/hardcoded-secret returned from a tool, via the same window heuristic plus brace-depth tracking of the returned object literal), and **secret-handling**'s secret-in-log check (`console.*`/`logger.*` calls with a secret-named argument; hardcoded-secret-value scanning was already language-agnostic). **Not covered for JS/TS, by deliberate scope decision:** codegen-injection (the mcp-factory class is inherently a Python-Jinja pattern) and auth-posture (bind/debug/mutating-route checks are inherently Flask/FastAPI-decorator-shaped; an Express/Fastify equivalent is new detector logic, not JS parity of the existing one -- left for a future increment, not attempted here). Jinja templates remain regex-level as before.

## Tests

```bash
python -m pytest -q     # 129 tests (122 passing, 7 self-audit skip without the env var below): per-detector vuln/clean fixtures (Python + JS/TS parity) + the reachability-grading matrix + the tool-parameter taint-tracking matrix (intra-file + cross-file, up to two hops) + the self-audit proof + client-report renderer
```

The self-audit tests (7 of the 129) require `MCP_SCANNER_FLEET_ROOT` to be set
and pointed at real MCP server repos to scan; they skip cleanly if it's
unset (e.g. in a fresh clone or CI on another machine). See
[ANNOUNCEMENT.md](ANNOUNCEMENT.md) for the reproducible self-audit output.

Each detector ships a matched pair of fixtures — a vulnerable one it must catch, a clean one it must not flag — so the false-positive floor is a tested invariant, not a hope.
