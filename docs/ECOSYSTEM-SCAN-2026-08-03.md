# MCP Ecosystem Scan — Before / After

**A raw scanner finding-count overstates real risk. Here is us publishing our own false
positives, and then closing them.**

On 2026-07-23 we scanned 13 popular public MCP-server repositories and wrote up the results.
That report named eight false-positive classes the scanner had produced. This report re-runs
the same 13 targets at today's scanner and shows what happened to each one.

| | |
|---|---|
| BEFORE scanner | `mcp-security-scanner` @ `15b5460` (2026-07-23) |
| AFTER scanner | `mcp-security-scanner` @ `59c8fd3` (2026-08-03) |
| Re-scan date | 2026-08-03 |
| Targets | the same 13 repos, re-cloned at their 2026-08-03 HEADs (SHAs below) |
| Commits between | 65 total, 40 touching `mcp_scanner/` |

---

## The headline

**The number that matters fell by two thirds. The raw number went up.**

| Metric | BEFORE | AFTER | Change |
|---|---|---|---|
| Raw findings, all severities | 1,170 | 1,448 | +278 |
| **Findings that qualify for the default `--fail-on` gate** (P0/P1, excluding CLI-only) | **200** | **66** | **−67%** |

Those two rows move in opposite directions, and that is the entire point of this report.

The raw count rose because the scanner learned to look at more code (recall work — see
"What made the raw count go up"). The gate-relevant count fell because the scanner learned to
tell you which findings are actually about the MCP tool surface and which are the maintainer's
own build scripts and test fixtures.

A tool that reports 1,448 problems is not more useful than one that reports 1,170. A tool that
can tell you which 66 of 1,448 to read first is.

---

## Isolating the scanner from the targets

The 13 targets moved upstream in the 11 days between the two scans, so a naive before/after
comparison confounds "our scanner changed" with "their code changed". We separated the two by
running the **old** scanner against the **new** clones, giving three columns:

- **A** — old scanner `15b5460` @ the 2026-07-23 target HEADs *(the published BEFORE)*
- **B** — old scanner `15b5460` @ the 2026-08-03 target HEADs *(isolates target drift)*
- **C** — scanner `59c8fd3` @ the 2026-08-03 target HEADs *(today)*

`B − A` is pure target drift. `C − B` is pure scanner delta, measured on byte-identical
checkouts.

| | A (old/old) | B (old/new) | C (new/new) | scanner delta (C−B) |
|---|---|---|---|---|
| Files scanned | 6,154 | 7,182 | 7,182 | 0 |
| **Raw findings** | **1,170** | **1,203** | **1,448** | **+245** |
| P0 | 6 | 13 | 13 | 0 |
| P1 | 194 | 180 | 295 | +115 |
| P2 | 969 | 1,009 | 1,134 | +125 |
| P3 | 1 | 1 | 6 | +5 |
| confidence: high | 365 | 367 | 220 | −147 |
| confidence: medium | 470 | 503 | 274 | −229 |
| confidence: low | 335 | 333 | 954 | +621 |
| reachability: reachable | 317 | 322 | 315 | −7 |
| reachability: unknown | 853 | 881 | 388 | −493 |
| reachability: **cli-only** | 0 | 0 | **745** | **+745** |
| Above-LOW confidence (review queue) | 835 | 870 | 494 | −376 |
| **Gate-qualifying (P0/P1, not CLI-only)** | **200** | **193** | **66** | **−127** |

Target drift accounts for +33 findings. The scanner accounts for +245. Of the total 1,170 → 1,448
move, target drift is 12% of it.

The three rows that carry the actual improvement:

- **745 findings are now graded `cli-only`** — a reachability grade that did not exist before.
  These are findings in build scripts, release tooling and test harnesses that cannot be reached
  from a registered MCP tool. Before, they sat in the same undifferentiated P1 queue as
  everything else. They are still reported; they are excluded from the default gate.
- **621 findings moved to LOW confidence.** The scanner still emits them. It no longer implies
  they are worth your afternoon.
- **The review queue (above-LOW confidence) fell from 835 to 494** while the raw count rose.

### Finding-level diff, B → C

Same targets, same SHAs, same files — so every difference below is the scanner and nothing else.
Findings keyed on `(repo, class, file, line)`; that key collapses 4 duplicate rows in B and 5 in
C, so the diff is computed over 1,199 and 1,443 respectively.

| | Count |
|---|---|
| Present in B, gone at HEAD (suppressed) | 74 |
| Present in both (common) | 1,125 |
| New at HEAD (recall expansion) | 318 |
| — of the common: severity demotions | 42 |
| — of the common: confidence demotions | 394 |
| — of the common: `unknown` → `cli-only` regrades | 481 |

Zero findings were promoted in severity or confidence.

---

## The eight false-positive classes: what happened to each

The 2026-07-23 report named eight FP classes. Five are closed, two are partial, one is open. We
are reporting the open one because a report that closes 8 of 8 on its own homework is not
evidence of anything.

Every commit below was verified by reading the diff and confirming the mechanism is present at
`59c8fd3`, not by trusting the commit subject.

| # | False-positive class | Status | Closing commit(s) | Evidence in this re-scan |
|---|---|---|---|---|
| 1 | "Read-only" doc/proxy tools flagged as ungated mutating tools | CLOSED | `2df84e1`, `9b1abe6`, `673af85` (07-23) | 5 tool-scope-creep findings regraded; no target-instance of the exact proxy shape — see caveat |
| 2 | Custom in-body permission checks not recognised as gates | **OPEN** | none | unchanged |
| 3 | Self-declared `destructiveHint` tools flagged as if undisclosed | PARTIAL | `4c3d429` (07-23) | annotation is read, but only in `job_hazards` |
| 4 | Pagination cursors tripping the secret-name heuristic | CLOSED | `c3b923a` (07-23) | 2 `next_token` findings gone; 1 `secret-in-log` on a `next_token` boolean gone |
| 5 | Maintainers' own build/release tooling flagged | PARTIAL | `2b28a14` (07-29) + the `cli-only` grade | 40 shell-injection findings demoted P1→P2; 481 regraded `cli-only` |
| 6 | `RegExp.prototype.exec()` read as `child_process.exec()` | CLOSED | `de787cf`, `e40a821` (07-23) | **exactly 3 findings gone**, all regex-receiver `.exec()` |
| 7 | AWS's own public example credential pair | CLOSED | `de8cf9b` (07-23), hardened by `31c3346`, `3d2b919` | **58 findings gone**, multiplicity-matched to the placeholder literal |
| 8 | Self-signed TLS test certificate flagged as a tracked secret | CLOSED | `d54655c`, `264ce77`, `58c8f5d` (07-23) | `cert.pem` + `key.pem` demoted high → low |

### The evidence, class by class

**Class 6 — `RegExp.exec()` vs `child_process.exec()` (CLOSED).** The old report said this was
"observed 3 times". The re-scan removes exactly three findings, and all three are a regex
receiver:

```
GLips/Figma-Context-MCP  scripts/scan-hidden-chars.mjs:133   while ((cfMatch = cfPattern.exec(line)) !== null) {
GLips/Figma-Context-MCP  scripts/scan-hidden-chars.mjs:156   while ((commentMatch = HTML_COMMENT_RE.exec(content)) !== null) {
wonderwhy-er/DesktopCommanderMCP  src/search-manager.ts:578  while ((m = wtRe.exec(xml)) !== null) {
```

All three were P1/high. Mechanism at HEAD: `_js_is_real_exec_call()` in
`mcp_scanner/detectors/param_injection.py` resolves the receiver through scope-aware bindings; a
receiver bound to `new RegExp(...)` or a `/pattern/` literal in the same scope demotes, while
`child_process` receivers and unresolvable receivers stay flagged. Correction to the old report:
this was 2 repos, not 1. Tests: `tests/test_param_injection_regexp_exec_fp.py`,
`tests/test_param_injection_regexp_scope_fp.py`.

**Class 7 — AWS's public example credentials (CLOSED).** 58 `hardcoded-secret` findings
disappeared, all in one target. Per-file counts match the number of occurrences of AWS's
canonical documentation placeholder access-key literal exactly:

| File | Findings removed | Placeholder-literal occurrences |
|---|---|---|
| `src/aws-serverless-mcp-server/tests/test_data_scrubber.py` | 9 | 9 |
| `src/aws-location-mcp-server/tests/test_server.py` | 8 | 8 |
| `src/iam-mcp-server/tests/test_server.py` | 8 | 8 |
| `src/amazon-translate-mcp-server/tests/test_config_comprehensive.py` | 6 | — |
| `src/amazon-translate-mcp-server/tests/test_aws_client.py` | 4 | 4 |
| `src/amazon-translate-mcp-server/tests/test_config.py` | 2 | 2 |

(Occurrence counts were obtained without printing any credential value.) Mechanism at HEAD:
`_KNOWN_PLACEHOLDER_SECRETS` in `mcp_scanner/detectors/secret_handling.py`, an exact-match
frozenset — a similar-but-real key still flags. A later adjudication (`31c3346`) narrowed the
companion `pragma: allowlist secret` path so a suppression comment demotes confidence but never
fully suppresses. Tests: `tests/test_secret_placeholder_fp.py`.

**Class 4 — pagination cursors (CLOSED).** Two `secret-leak-via-tool-response` findings gone,
both on an opaque continuation handle:

```
awslabs/mcp  .../amazon_translate_mcp_server/server.py:595
  return {'jobs': job_list, 'total_count': len(job_list), 'next_token': result_next_token}
```

A third `secret-in-log` finding on `f'Received next_token: {next_token is not None}'` also
cleared. Mechanism: `_is_pagination_cursor_name()` demotes only on a pagination word-shape
(`next`/`page`/`continuation` + `token`/`cursor`) *and* only when no stronger credential word
(`access`, `refresh`, `auth`, `secret`, `bearer`, `client`) is present in the same identifier.
Tests: `tests/test_secret_pagination_fp.py`.

**Class 8 — self-signed test certificate (CLOSED, by demotion not removal).**

```
microsoft/playwright-mcp  tests/testserver/cert.pem   P1/high -> P1/low
microsoft/playwright-mcp  tests/testserver/key.pem    P1/high -> P1/low
```

These are demoted, not dropped — deliberately. Mechanism requires *both*
`_is_self_signed_test_cert()` (issuer == subject, parsed via `cryptography.x509`) and
`_cert_has_test_shaped_identity()` (test markers in CN/SAN, ≤90-day validity, or a sub-2048-bit
key), and a later fix (`58c8f5d`) requires the key and cert to be cryptographically paired
rather than merely co-located. It fails closed: a missing `cryptography` package, a parse error,
or a production-shaped cert sitting under `tests/` all stay flagged. Tests:
`tests/test_secret_selfsigned_cert_fp.py`.

**Class 5 — maintainers' own build and release tooling (PARTIAL).** This is the largest class by
volume and it was addressed by *grading*, not by suppression:

- 40 `shell-injection` findings demoted P1 → P2 and high → low.
- 481 findings regraded `unknown` → `cli-only`, which excludes them from the default gate.
- `2b28a14` demotes `rm -rf` to P3 when every target on the line is an exact-match curated
  build-artifact name (`node_modules`, `dist`, `.venv`, `__pycache__`, archive suffixes) and
  fails closed on any variable, glob or unrecognised target.

Still open within this class: `git push --force` and `git reset --hard` against a maintainer's
own release branch are still flagged unconditionally — the detector has no notion of "your own
branch". Calling this class fully closed would be a false claim.

**Class 3 — self-declared `destructiveHint` (PARTIAL).** `4c3d429` teaches the scanner to read
the MCP `destructiveHint` annotation, but only in `job_hazards.py`, and by explicit design it
appends an explanatory note and **never** suppresses or downgrades. `readOnlyHint` is not read
anywhere. The original complaint was about a computer-use-style server's tools flagged by
`tool_scope_creep` — that path still has no annotation awareness. The fix landed adjacent to the
reported problem, not on it.

**Class 2 — custom in-body permission gates (OPEN).** The old report's example was a tool
genuinely guarded by `if <readonly-mode-check>: return "not permitted"` in the tool body. The
gate-recogniser (`_GATE_HINT` in `tool_scope_creep.py`) still matches a fixed keyword list
against decorator source only. It is unchanged across all 40 commits. No test covers this shape.

The consequence is worth restating plainly, because it is the honest limit of this whole tool:
**a "no visible permission gate" finding from this scanner is not proof a tool is unguarded.**
It means "no gate this scanner's heuristic recognises," which is a weaker claim.

**Class 1 — read-only doc/proxy tools (CLOSED, with a caveat).** The fix is real and verified:
`_is_mutating_sink_call` now matches a resolved `module.attr` dotted chain via
`_resolved_sink_name`, never a bare-name substring test. The original bug flagged a helper merely
*named* `_run_subprocess` as a subprocess sink. Caveat: we cannot point at a specific instance of
this exact FP disappearing from these 13 targets — 5 `tool-scope-creep` findings were regraded,
but the class was originally verified against a different repo. The mechanism is closed; the
in-corpus demonstration is not.

---

## What made the raw count go up

+318 findings are new at HEAD on byte-identical checkouts. None of these are FP fixes; they are
recall work, and they are why the raw total rose:

| Commit | Date | Effect |
|---|---|---|
| `d3c9a9d` | 07-30 | un-gates `secret_handling`'s name-based branch from the Python AST, so it runs on JS/TS — **+214 `hardcoded-secret`** |
| `5654cb3` | 07-30 | un-gates `auth_posture`'s text-shaped checks from the Python AST — **+90 `network-exposure`**, +4 `no-rate-limit` |
| `42b61da` | 07-30 | tool-registry extraction for the five real MCP registration idioms (`registerTool`, `addTool`, `setRequestHandler`, FastMCP call-style, decorators) — +8 `tool-scope-creep` |
| `98501f8` | 07-29 | new `grade` axis: findings that could not be graded are labelled `ungraded` instead of rendering identically to graded ones |
| `b9e341a` | 07-29 | `cli-only` reachability grade as a fallback below the call-graph |
| `2326e9d` | 07-29 | shared test-path classifier, adds filename markers (`*.test.ts`, `*.spec.js`, `test_*.py`, `conftest.py`) |

Before `42b61da`, the tool-registry extractor recognised only the deprecated `server.tool()` JS
API and Python decorators — it missed four of the five idioms real servers use. A scanner that
cannot find a repo's tools cannot grade reachability for that repo, which is why 745 findings
could be moved to `cli-only` only after this landed.

At HEAD, 1,060 of 1,448 findings are graded and 388 are `ungraded`. The `ungraded` label is
itself new: previously an ungradeable finding looked exactly like a graded one.

---

## The one finding that was real

The 2026-07-23 report described a single genuinely reportable finding: a template/codegen
injection in a code-generation tool rendering a caller-influenced identifier into generated
source with Jinja `autoescape` disabled. It was deliberately not attributed.

It is public now, and not because of us. On 2026-07-31, **[awslabs/mcp#4384](https://github.com/awslabs/mcp/pull/4384)**
— "fix(dynamodb-mcp-server): validate and escape names in CDK generator", opened by
`LeeroyHannigan` — independently found and fixed the same issue, more completely than our draft
had: 9 interpolation sites against our 2, and it correctly separates identifier positions (which
need charset validation) from string-literal positions (which `tojson` handles). The PR was open
and unmerged as of 2026-08-03, at +476/−12 across 5 files.

Its primary file is
`src/dynamodb-mcp-server/awslabs/dynamodb_mcp_server/cdk_generator/generator.py`, which is the
exact file and the exact detector class our scanner still flags at HEAD:

```
awslabs/mcp  src/dynamodb-mcp-server/.../cdk_generator/generator.py:48  codegen-injection  P1/medium
```

We claim no credit for the discovery, and there was no coordination. We cite it as public record
for one narrow reason: it is independent, third-party corroboration that the `codegen_injection`
detector finds a real bug that a competent human reviewer independently judged worth fixing.

`codegen_injection.py` is **byte-identical** between `15b5460` and `59c8fd3`
(`git diff 15b5460 59c8fd3 -- mcp_scanner/detectors/codegen_injection.py` is empty). The detector
that found the one true positive was not touched by any of the FP work.

We have sent no disclosure and contacted no maintainer.

---

## Targets and SHAs

All 13 re-cloned `--depth 1` on 2026-08-03 and scanned read-only. Raw totals only — no severity
or class is attributed to a named repo, for the reason in "Scope and limits" below.

| Repo | Target SHA (2026-08-03) | Last commit | Files | A | B | C |
|---|---|---|---|---|---|---|
| modelcontextprotocol/servers | `76d64c822f5125032f89eb71dbdb94e42b434821` | 2026-07-29 | 145 | 18 | 18 | 29 |
| microsoft/playwright-mcp | `42e792a40faae2d99e51c9a190f8b016bd6ef0b2` | 2026-08-03 | 33 | 13 | 13 | 15 |
| PrefectHQ/fastmcp | `a7e9b709192d19a9c014d95ef4fbedc35befeeec` | 2026-08-03 | 1,509 | 103 | 108 | 128 |
| GLips/Figma-Context-MCP | `c083d65c7e002923e7cb98f4e3bdafb105e90f6d` | 2026-06-24 | 105 | 15 | 15 | 14 |
| awslabs/mcp | `ebd0a622eb1dc3faa111aad3b18027df50555dff` | 2026-08-03 | 3,703 | 540 | 540 | 584 |
| wonderwhy-er/DesktopCommanderMCP | `1eccc8b09cc09805202a1737fd20d605356c3671` | 2026-07-21 | 299 | 142 | 142 | 142 |
| firecrawl/firecrawl-mcp-server | `a9b6b943d1406e2b595fbf028499f903210d0d47` | 2026-08-04 | 41 | 9 | 22 | 36 |
| sooperset/mcp-atlassian | `ec543512fe6ac1b09dd77f6f5b36f0a3ae24366a` | 2026-08-03 | 415 | 94 | 94 | 120 |
| CursorTouch/Windows-MCP | `f8401f2e78eb5b058eceb38c94eaf835cb4318fb` | 2026-08-01 | 121 | 11 | 12 | 12 |
| getsentry/XcodeBuildMCP | `e6ef59b49b44012c824f0a0de261c96142e37390` | 2026-08-02 | 1,840 | 31 | 31 | 37 |
| modelcontextprotocol/inspector | `fb1b0cb41c7b19e08334025ce118d48af1394967` | 2026-07-28 | 1,048 | 28 | 39 | 85 |
| mcp-use/mcp-use | `16216399a82041c5d51025127c43e061c69ceea2` | 2026-08-03 | 1,979 | 166 | 169 | 246 |
| Coding-Solo/godot-mcp | `1209744fad78f3998f98c7394fd0f6ef50da5281` | 2026-04-16 | 11 | 0 | 0 | 0 |

"Files" is `git ls-files` at the recorded SHA. `Coding-Solo/godot-mcp` produced zero findings in
all three columns.

---

## Scope and limits

**Every number in this report was re-measured today.** The A column is the only figure carried
over from 2026-07-23, and it was re-derived from that run's retained `raw-results.json` rather
than copied from its prose.

**What we could not measure.** The 2026-07-23 run recorded no target SHAs and no scan metadata.
We therefore cannot reconstruct the exact upstream state it saw, and cannot run today's scanner
against the 2026-07-23 target SHAs. The B column exists to bound that gap — it shows target drift
is worth +33 findings on today's SHAs — but it is a bound, not a reconstruction. This report
records target SHAs precisely so the next before/after does not have this hole.

**Nothing here is a vulnerability claim about a named repository.** The 66 gate-qualifying
findings at HEAD have not been hand-audited. Raw per-repo totals are published because the delta
story requires them; severity and class are not attributed to a named repo, because an unreviewed
finding attributed to a project reads as an accusation and is not one. The single exception is
the `awslabs/mcp` codegen finding, and only because a third party made it public first.

**Standing scanner limits**, unchanged and worth repeating:

- Static only. No execution, no dynamic analysis. A clean bill means no critical/high *static*
  pattern was found, not that a server is safe at runtime.
- JS/TS coverage is regex-based, not AST-based. Class 6 above was a direct consequence of that,
  and the fix is a scope-aware heuristic, not a parser.
- Gate recognition is pattern-based. See class 2: a project-specific custom gate goes
  unrecognised.
- Taint and reachability resolution is bounded (one hop for the tool-scope-creep and secret-leak
  SDK path, two for taint). Deeper flows are labelled `unknown` — never guessed.
- The scanner does not read `readOnlyHint`, and reads `destructiveHint` in one detector only.

---

## Reproducing this

The target list, the clone scratch dir and all scan artifacts are gitignored by design — the
scanner's disclosure rails keep third-party names and raw findings out of the tracked tree, and
promoting an aggregate is an operator decision rather than something the tool does. To rebuild:

1. Copy `ecoscan-targets.json.example` to `ecoscan-targets.json` and fill in the 13 repos above.
2. `git clone --depth 1` each target and check out the SHA in the table.
3. `PYTHONPATH=. python -m mcp_scanner.cli ecosystem-scan --config ./ecoscan-targets.json`

Artifacts land in `ecoscan-artifacts/`. Note that `ecoscan-targets.lock.json` in this repo pins a
**different** measurement — the 5 held-out targets behind the precision claim in `README.md` —
and is not the input to this scan.

## Bottom line

Across 13 well-known public MCP servers, over 11 days and 40 commits to the analysis code: the
raw finding count went **up** by 24% and the count of findings worth your attention went **down**
by 67%. Eight false-positive classes were published; five are closed with in-corpus evidence, two
are partial, and one is still open and named as such.

A scanner honest about its false positives is more trustworthy than one reporting a scarier
number nobody checked. The way to demonstrate that is not to assert it — it is to publish the
false positives, then publish the commits that closed them, then re-run and show the delta.
