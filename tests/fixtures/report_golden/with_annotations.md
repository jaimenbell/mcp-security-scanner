# Week-1 Audit -- Acme Corp

## 1. Engagement & scan metadata

| | |
|---|---|
| Client | Acme Corp |
| Engagement | Week-1 Audit |
| Scope | 1 MCP server |
| Target | `C:/scans/acme-mcp` |
| Scan date | 2026-07-23 |
| Scanner version (git) | `88b133c` |
| Scanner test suite at that version | 346 tests (337 passing, 9 environment-gated skips) |
| Triage annotations | triage.toml |
| Reviewed by | Jaimen |

## 2. Executive summary

The scanner produced 3 raw finding(s) across 14 scanned file(s) in `acme-mcp`. After human triage, 1 are confirmed real, 1 were dismissed as false positives, 1 accepted as risk, 0 already mitigated, and 0 remain unreviewed. 1 confirmed critical/high finding(s) require action.

`acme-mcp` does not get a clean bill on the raw scan: 1 critical (P0) and 1 high (P1) finding(s) before triage. The triage summary below is the honest read of how many survive human review.

**Severity legend:** **P0** = Critical -- exploitable now, no preconditions; **P1** = High -- exploitable with attacker-reachable but currently-unmet conditions; **P2** = Medium -- defense-in-depth gap / conditional; **P3** = Low -- hardening nit.

| Severity | Confirmed | False positive | Accepted risk | Mitigated | Unreviewed | Raw |
|---|---|---|---|---|---|---|
| P0 | 1 | 0 | 0 | 0 | 0 | 1 |
| P1 | 0 | 0 | 1 | 0 | 0 | 1 |
| P2 | 0 | 1 | 0 | 0 | 0 | 1 |
| P3 | 0 | 0 | 0 | 0 | 0 | 0 |

Reachability of the raw findings (per severity): P0: 1 reachable; P1: 1 reachable; P2: 1 unknown; P3: none.

**Top-3 risks (confirmed first, then unreviewed):**

1. **[P0/Confirmed]** `srv/tools.py:42` -- a tool handler that passes caller-influenced input into a dangerous sink (shell, eval, unsafe deserialization, or an unguarded fetch/file path) (`2de1378d5d7a`).

## 3. Triage summary

What the raw number would have misled you about: 3 raw finding(s) reduce to 1 confirmed after human triage -- the raw count alone would have overstated the real risk surface by 2 finding(s).

| Verdict | Count |
|---|---|
| Confirmed | 1 |
| False positive | 1 |
| Accepted risk | 1 |
| Mitigated | 0 |
| Unreviewed | 0 |
| **Raw total** | 3 |

**False-positive classes encountered** (each dismissal carries the reviewer's reasoning -- this is what separates a triaged report from a pattern dump):

- `secret-handling`:
  - `tests/conftest.py:7` (`e28dfff3c483`) -- Obviously-fake fixture token in the test suite; scanner already demoted it (fake-marker).

## 4. Findings detail

### `2de1378d5d7a` -- subprocess with shell=True on a tool parameter

- **Severity / confidence:** P0 / high
- **Verdict:** Confirmed (reviewed by Jaimen)
- **Reviewer note:** Reproduced by hand: the run_command tool's cmd parameter reaches the shell unmodified.
- **Class:** `param-injection`
- **Location:** `srv/tools.py:42`
- **Reachability / taint:** reachable / tainted
- **What was found:** subprocess.run(cmd, shell=True) where cmd derives from the run_command tool's parameter
- **Evidence:** `subprocess.run(cmd, shell=True)`
- **Specific fix:** Use an argv list; never shell=True on caller-influenced input.
- **Class remediation guidance:** Never pass caller-influenced input to a shell (`shell=True`, `os.system`), `eval`/`exec`, `pickle.load`, or unsafe `yaml.load`. Use argv lists for subprocesses, `SafeLoader` for YAML, and validate/allowlist any path or URL a tool parameter can reach.

### `ef3a4cf8b6b2` -- mutating tool registered with no visible gate

- **Severity / confidence:** P1 / medium
- **Verdict:** Accepted risk (reviewed by Jaimen)
- **Reviewer note:** Deliberate admin tool; deployment is tailnet-only. Revisit if exposure changes.
- **Class:** `tool-scope-creep`
- **Location:** `srv/tools.py:88`
- **Reachability / taint:** reachable / unknown
- **What was found:** delete_records is a mutating @mcp.tool() with no permission-group gate or env-flag opt-in in its file
- **Evidence:** `@mcp.tool()`
- **Specific fix:** Gate the tool behind an explicit permission group, default OFF.
- **Class remediation guidance:** Gate every mutating MCP tool behind an explicit permission group or env-flag opt-in, default OFF. A tool the LLM can call is an attacker-reachable surface; register write capabilities separately from read capabilities.

### `e28dfff3c483` -- hardcoded secret assignment

- **Severity / confidence:** P2 / low
- **Verdict:** False positive (reviewed by Jaimen)
- **Reviewer note:** Obviously-fake fixture token in the test suite; scanner already demoted it (fake-marker).
- **Class:** `secret-handling`
- **Location:** `tests/conftest.py:7`
- **Reachability / taint:** unknown / unknown
- **What was found:** TEST_TOKEN assigned a secret-shaped literal (fake-marker)
- **Evidence:** `TEST_TOKEN = "fake-test-token-do-not-use"`
- **Specific fix:** Move to an env var, or keep as an obviously-fake fixture value.
- **Class remediation guidance:** Move secrets out of tracked files and source literals into environment variables or a secret manager; never pass a secret to `print`/`log.*`. Rotate anything that was ever committed -- removal from the working tree does not un-leak it.

## 5. Methodology & honest capability boundary

Stated plainly so the tool-vs-expert split is contractual, not verbal:

**Static analysis only.** Every finding comes from reading the target's git-tracked source (Python AST for the deep path; regex for Jinja/JS/TS/YAML/PowerShell/bash surfaces). No code is executed, no server is run, and no finding is proven exploitable at runtime -- findings are a prioritized review queue, not a verdict.

**Manifest-aware tool reachability grading.** After the detectors run, the scanner discovers registered MCP tools (decorator registrations, the low-level SDK's Server()/list_tools/call_tool shape, and any server.json manifest) and walks a static call-graph to label each finding reachable, cli-only, uncalled, or unknown. Reachable raises a finding's confidence; the others lower it; a finding is never dropped on this basis. Limits: the same-file call-graph is exact, cross-file is best-effort; module-level code, non-Python findings, ambiguous low-level-SDK dispatch, and repos with no discoverable tools are labelled unknown rather than guessed.

**Tool-parameter taint tracking v1.** A second pass seeds every registered tool handler's parameters as taint sources and propagates them through assignments, f-strings/concat/format, containers, and same-repo calls into the dangerous sinks, labelling findings tainted / untainted / unknown (again nudging confidence, never dropping). Limits, stated plainly: same-file dataflow is transitive but cross-file follows at most two direct-import hops (no third hop, no cross-repo flow); it is NOT sanitizer-aware (a validated/escaped value still counts as tainted, by design over-flagging); and dynamic dispatch (getattr / *args / **kwargs), decorator transforms, and non-Python surfaces are labelled unknown.

**Confidence is load-bearing.** This is a deliberately over-flagging scanner: low-confidence findings mean 'a human should glance at this' and produce false positives by design. The triage pass in this report is where a human separates the two -- the raw finding count is not the risk count.

**The one law of suppression.** Full suppression is reserved for the scanner's OWN curated exact-match judgment (e.g. documented SDK placeholder credentials, pagination-cursor field names, provably self-signed test certificates with test-identity CN/SAN). Every other signal -- a target-authored suppress comment, an obviously-fake value marker, a cert's test path -- may only demote confidence and tag the finding; it may never make a finding disappear. This matters because the scanner's use case is third-party, possibly-adversarial repos.

**Not a git-history scanner.** The secret detector reads the tracked working tree only -- it does not see credentials that were committed and later removed. Pair it with gitleaks for history scanning.

**Language coverage.** Deep (AST-based) for Python. JS/TS (.js/.mjs/.cjs/.ts/.mts/.cts/.jsx/.tsx) is line-based regex, not a parse tree: four detector families have JS/TS parity on that regex basis (param-injection, tool-scope-creep, secret-leak-via-tool-response, secret-in-log), while codegen-injection and auth-posture remain Python-only by scope decision. Jinja templates are regex-level. Known regex-heuristic gaps (e.g. optional-chaining eval, spread-of-secret returns) are documented in the README rather than silently missed.

**Every finding needs a human.** No dynamic analysis means no proof of exploitability: every finding in this report was either confirmed, dismissed, or left unreviewed by a named human triage pass, and the report says which, per finding. A clean bill means no critical/high patterns were found by these detectors -- not a guarantee of security.

## 6. Appendix

### Detector families

| Class | What it checks |
|---|---|
| `codegen-injection` | Jinja `autoescape` off in a code-generating tool; hand-rolled string escaping instead of a real serializer. |
| `param-injection` | `subprocess(shell=True)`, `os.system`, non-constant `eval`/`exec`, `pickle.load`, unsafe `yaml.load`, SSRF, path traversal. |
| `auth-posture` | Bind `0.0.0.0` (+debug escalation), `debug=True`, mutating routes with no auth dependency, no rate limiter. |
| `secret-handling` | Tracked `.env`/`.pem`/`.key`/keypair files, hardcoded secret-shaped literals, secrets passed to `print`/`log.*`. |
| `tool-scope-creep` | A mutating `@mcp.tool()`-registered tool (by verb-name heuristic or a dangerous body sink, one hop through a delegated helper) with no visible permission-group gate or env-flag opt-in anywhere in its file or the helper it calls. |
| `secret-leak-via-tool-response` | A tool's `return` value that hands back `os.environ`, a whole config/settings object (`vars()`/`asdict()`/`__dict__`), a secret-named field, or a hardcoded secret-shaped literal to the calling LLM. |
| `job-hazards` | Scheduled jobs/wrappers/IaC-CI files (cron, systemd, GitHub Actions, PowerShell/bash/batch deploy scripts): over-broad credential/ACL scope, a destructive call with no confirm-before-destroy gate, and success reported without verification (`\|\| true`, bare `exit 0`, `continue-on-error`, empty `catch {}`). |

### Scan configuration

- Target: `C:/scans/acme-mcp`
- Files scanned: 14
- Scanner version: `88b133c`
- Scan notes/errors: none

### Annotation provenance

- Annotations file: `triage.toml`
- Annotations applied to findings in this scan: 3
- Annotations referencing unknown ids: 0
- Reviewers: Jaimen
