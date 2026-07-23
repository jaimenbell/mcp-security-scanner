---
title: MCP Server Security Scanner
type: product-readme
status: prototype
---

# mcp-security-scanner

[![CI](https://github.com/jaimenbell/mcp-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jaimenbell/mcp-security-scanner/actions/workflows/ci.yml)

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
python -m mcp_scanner.cli <path> --fail-on P1 --include-cli-only-in-gate  # also gate on cli-only findings
python -m mcp_scanner.cli --self-audit                  # scan your own fleet's servers
```

`--fail-on` excludes `reachability: cli-only` findings by default — a
cli-only finding's only known caller traces to a non-tool entrypoint (argv/
CLI-main, an admin script, a test file), never a registered MCP tool, so it
does not block a build gate unless your CLI/admin surface is itself part of
the attacker-reachable scope you want gated (a publicly-exposed management
CLI, say) — pass `--include-cli-only-in-gate` to opt back in.

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

- **Manifest-aware reachability (built 2026-07-21; low-level MCP SDK shape added 2026-07-23, N-vote-hardened across two rounds the same day).** After the detectors run, the scanner discovers the registered MCP tools (`@mcp.tool()` / `server.tool(...)` registrations, the low-level SDK's `Server()` + `@server.list_tools()`/`@server.call_tool()` + `types.Tool(...)`/bare `Tool(...)` shape, and any `server.json` manifest) and walks a static call-graph to label every finding **reachable** (inside a tool handler or a function transitively called from one), **unreachable-by-tools** (no call path from any registered tool), or **unknown**. `reachable` raises a finding's confidence; `unreachable` lowers it; a finding is **never dropped** on this basis (the over-flag philosophy stands). Stated limits: the same-file call-graph is exact; cross-file is best-effort by function name (not a resolved import graph); module-level code, non-Python (JS/TS/YAML/shell) findings, and repos with no discoverable tools are labelled `unknown` rather than guessed. It labels *reachability*; the separate taint pass (below) tracks the individual tainted value. The low-level-SDK discovery's `Tool()`-construction-to-dispatcher correlation is scoped to a single file/module (never a repo-wide guess across multiple dispatchers) and gated on the file actually importing something from the `mcp` package (so a same-named non-MCP class can't flip `has_tools` or claim a bogus root) -- round 1 of N-vote review caught a repo with more than one low-level dispatcher, or a coincidental `Tool`/`call_tool` name from an unrelated framework, downgrading a genuinely reachable finding to a lower-confidence grade; round 2 (Opus final-verify) caught two further shapes that still manufactured or leaked a bogus root -- a split declaration-module/dispatch-module layout (the list_tools fallback was rooting reachability at the metadata-only list_tools handler, since removed outright) and a repo mixing one genuinely ambiguous dispatcher with an unrelated valid one elsewhere (the repo-wide `has_tools`/`have_py_handlers` check was letting the valid root "unlock" confident grading for the un-rooted tool too). Fixed by treating an un-rooted `py-lowlevel-sdk` registration exactly like unresolved dynamic dispatch: withhold CLI_ONLY/UNCALLED in favor of UNKNOWN. All four shapes are regression-tested. **Coverage gap closed (2026-07-23, later same day):** detector 5 (write-tools-on-by-default / tool-scope-creep) and detector 6 (secret-leak-via-tool-response) used to consume only decorator-style registration (JS-regex entries for scope-creep; a private `@mcp.tool()` walk for secret-leak) and produced zero findings for a repo using *only* the low-level SDK shape. Both now treat a provenance-gated `@server.call_tool()` handler as an inspection root via the shared `tool_registry.dispatch_segments` helper: it splits the handler's body into per-tool branches from a top-level `if name == "x": ... elif name == "y": ...` dispatch chain. A branch attributable to exactly one literal tool name is analyzed (mutating-sink/gate for scope-creep; leak-shaped-return for secret-leak) and attributed to that tool; a branch that isn't attributable (an `in (...)` test, the final `else`, code outside the if/elif chain, or no dispatch shape at all -- a dict-keyed dispatch table / `match`/`case`) is still analyzed but attributed to the dispatch handler itself, never guessed at one tool -- the same never-guess-a-root discipline as the reachability fix above. secret-leak-via-tool-response additionally follows one hop into a helper function a branch plainly delegates to (mirroring `tool_scope_creep.py`'s existing one-hop helper-delegation convention), since a low-level dispatch branch's leak is often in the helper's own return, not the branch's. **Known boundary, disclosed rather than silently left:** only a literal `==` if/elif walk counts as attributable dispatch (no real dataflow); a gate found anywhere in the handler's decorator/body text is treated as gating every branch in that handler, a deliberately coarse heuristic (matching the existing module-level gate's breadth), not per-branch proof.
- **Tool-parameter taint tracking v1 (built 2026-07-21; cross-file budget raised 2026-07-22).** A second post-detector pass seeds every registered tool handler's parameters as taint **sources** and propagates them through assignments, f-strings/concat/`.format()`, common containers, and same-repo function calls into the param-injection **sinks** (subprocess/`os.system`/`eval`/`exec`/`pickle`/`yaml.load`/HTTP-fetch/`open`). Each such finding is labelled **tainted** (a tool parameter provably reaches the sink), **untainted** (the sink is in tool-reachable code but fed a constant / other source), or **unknown**. `tainted` raises confidence; `untainted` lowers it; a finding is **never dropped** (the over-flag philosophy stands — an `untainted` sink is still reported, just lower-confidence). Stated limits, honestly: same-file dataflow is transitive, and cross-file follows **up to two direct-import hops** (no third hop, no cross-repo flow); it is **not sanitizer-aware** (a validated/escaped value is still treated as tainted, by design); and it does not model dynamic dispatch (`getattr` / `*args` / `**kwargs` re-binding), decorator transforms, module-level code, or non-Python surfaces — all labelled `unknown` rather than guessed. Deeper (3+ hop) and cross-repo taint remain out of scope.
- **Static only.** No dynamic analysis. Reachability and taint are inferred from the static call-graph above, not observed at runtime.
- **Confidence is load-bearing.** `low` findings are "a human should glance at this," and produce false positives by design (e.g. a variable file path in a test file). They are P2/P3 and never break a clean bill.
- **Not a git-history scanner.** The secret detector reads the tracked working tree, not full history. Pair it with `gitleaks` for history.
- **Language coverage (updated 2026-07-22).** Deep for Python (AST-based). JS/TS has no AST path in this scanner -- it is line-based regex (shared helpers in `mcp_scanner/js_util.py`), the same approach `job_hazards.py` already used for its non-Python file types. Collected extensions (`js_util.JS_SUFFIXES`, shared by `scanner.py`'s `_SCAN_SUFFIXES` and `tool_registry`): `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, `.tsx` -- `.jsx`/`.tsx` JSX syntax (attribute `{...}` braces, `{cond && <X/>}` conditional-render braces, `{/* JSX comment */}`) was verified, not assumed, not to trip the brace/string-aware helpers: `tests/fixtures/vuln_tsx_dashboard` mixes a real eval() sink, an ungated mutating tool, and a secret-named return field with a realistic JSX render block, and every finding lands on the sink line, none inside the JSX; `clean_tsx_dashboard` carries the identical JSX shapes with safe code and stays fully quiet. Four detector families now have JS/TS parity on this regex basis: **param-injection** (exec/execSync always-shell -- including `node:child_process` and destructure-aliased bindings, e.g. `const { exec: run } = require(...)` -- spawn/execFile with `shell:true`, `eval()`/`new Function()`, `yaml.load` without a safe schema, fetch/axios/http(s).get SSRF, fs read/write path-traversal), **tool-scope-creep** (mutating `server.tool(...)` registrations with no gate, via a capped line-window heuristic standing in for a real function-body scope; gate-hint matching is comment-stripped so a `// TODO: needs auth_required` note can't suppress a finding), **secret-leak-via-tool-response** (`process.env`/whole-config/secret-named/hardcoded-secret returned from a tool -- same-line compressed object literals and multi-line returns alike -- via the same window heuristic plus a string-literal-aware brace-depth tracker), and **secret-handling**'s secret-in-log check (`console.*`/`logger.*` calls with a secret-named argument, word-boundary-guarded against a name that merely contains a secret-vocabulary substring; hardcoded-secret-value scanning was already language-agnostic). **Not covered for JS/TS, by deliberate scope decision:** codegen-injection (the mcp-factory class is inherently a Python-Jinja pattern) and auth-posture (bind/debug/mutating-route checks are inherently Flask/FastAPI-decorator-shaped; an Express/Fastify equivalent is new detector logic, not JS parity of the existing one -- left for a future increment, not attempted here). Jinja templates remain regex-level as before.
- **Known JS/TS regex-heuristic gaps (documented, not built -- 2026-07-22 adversarial review, both waves; extension gap closed 2026-07-22, see Language coverage above).** Stated honestly rather than silently missed: optional-chaining eval (`globalThis?.eval?.()`) isn't matched by the `eval(` sink regex; a spread-of-secret-variable return (`return {...apiKey}`) isn't decomposed the way a named key is, and neither is the equivalent `return Object.assign({}, {apiKey: process.env.API_KEY})` shape (same family -- a secret-named key wrapped in a call other than a plain object literal); `tool_registry`'s JS registration regex is comment-blind, so a commented-out `// server.tool('foo', ...)` still registers a phantom tool -- an over-flag, the direction this scanner already accepts, not an under-flag; and the JS registration-window heuristic used by tool-scope-creep / secret-leak-via-tool-response is documented as "40 lines" but is actually 41 (`start` through `start + 40` inclusive) -- a cosmetic off-by-one in the docstring, not a functional gap.

## Tests

```bash
python -m pytest -q     # 253 tests (246 passing, 7 self-audit skip without the env var below): per-detector vuln/clean fixtures (Python + JS/TS parity across .js/.mjs/.cjs/.ts/.mts/.cts/.jsx/.tsx) + the reachability-grading matrix (incl. the cli-only/uncalled decidable-reachability grades + the low-level MCP SDK Server()/list_tools/call_tool discovery shape, per-module-scoped and import-provenance-gated so a repo with more than one dispatcher, or a same-named non-MCP class, can't claim a bogus root, and an un-rooted low-level tool -- split declaration/dispatch modules, or a genuinely ambiguous multi-dispatcher file -- withholds CLI_ONLY/UNCALLED in favor of UNKNOWN the same way unresolvable dynamic dispatch does) + detector 5 (tool-scope-creep) and detector 6 (secret-leak-via-tool-response) low-level-SDK dispatch-branch attribution (2026-07-23: `tool_registry.dispatch_segments`, shared by both detectors) + the tool-parameter taint-tracking matrix (intra-file + cross-file, up to two hops) + the self-audit proof + client-report renderer + the CI README count-verification gate's own unit tests
```

CI (`.github/workflows/ci.yml`) runs this suite on every push/PR and fails the
build if this claimed count drifts from what the suite actually reports --
see `scripts/check_readme_counts.py`.

The self-audit tests (7 of the 253) require `MCP_SCANNER_FLEET_ROOT` to be set
and pointed at real MCP server repos to scan; they skip cleanly if it's
unset (e.g. in a fresh clone or CI on another machine). See
[ANNOUNCEMENT.md](ANNOUNCEMENT.md) for the reproducible self-audit output.

Each detector ships a matched pair of fixtures — a vulnerable one it must catch, a clean one it must not flag — so the false-positive floor is a tested invariant, not a hope.
