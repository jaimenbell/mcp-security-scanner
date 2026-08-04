# Hand-audit of the 66 gate-qualifying findings — 2026-08-03

This is the per-finding record behind the addendum in
[`ECOSYSTEM-SCAN-2026-08-03.md`](./ECOSYSTEM-SCAN-2026-08-03.md). It exists
because the addendum prints a verdict split, and a verdict split nobody can
open is exactly the kind of number that report argues against.

**What was audited.** The 66 findings that qualify for the default
`--fail-on` gate in the 2026-08-03 ecosystem scan — severity `P0` or `P1`,
excluding `reachability: cli-only` (`mcp_scanner/cli.py::_exit_code`).
They were produced by scanner commit `59c8fd3` against the 13 target SHAs
published in the scan report.

**Method.** Each finding was opened against the cloned target's real source
at the published SHA and judged on that source, not on the scanner's own
`snippet` or `detail` field. Verdicts are one reader's judgement, recorded
per finding so they can be argued with.

**Verdict definitions.**

| verdict | means |
|---|---|
| **real defect** | the pattern is present and a maintainer would plausibly want it fixed — caller-influenced input reaching a dangerous sink, or a genuine live credential |
| **real, not a vuln** | the pattern is genuinely present as described, but is not a meaningful vulnerability in context: the tool's advertised purpose, CI/test-only code, a placeholder, or an operator-bounded capability |
| **false positive** | the scanner was factually wrong about the code — the pattern is absent, the match is an identifier rather than a value, a guard governs the sink, or the polarity is inverted |

Where a call was genuinely close, the audit took the lower-alarm option.
That biases the `real defect` count **down**, deliberately.

## Totals

| verdict | findings | share |
|---|---|---|
| real defect | 2 | 3% |
| real, not a vuln | 28 | 42% |
| false positive | 36 | 55% |
| **total** | **66** | **100%** |

## By detector class

| detector class | findings | real defect | real, not a vuln | false positive |
|---|---|---|---|---|
| `hardcoded-secret` | 26 | 0 | 7 | 19 |
| `tool-scope-creep` | 17 | 0 | 5 | 12 |
| `job-destructive-no-confirm` | 14 | 0 | 11 | 3 |
| `code-eval` | 3 | 0 | 3 | 0 |
| `codegen-injection` | 2 | 2 | 0 | 0 |
| `network-exposure` | 2 | 0 | 2 | 0 |
| `secret-leak-via-tool-response` | 1 | 0 | 0 | 1 |
| `tracked-secret-file` | 1 | 0 | 0 | 1 |

## Per finding

No repository, file path or line number appears below, for the reason given
in the scan report's "Scope and limits": an unreviewed finding attributed to
a named project reads as an accusation. `finding_id` is stable across runs of
the same scanner, so a reader who reproduces the scan can join this table
back to their own output.

| finding_id | class | sev | scanner confidence | verdict | why |
|---|---|---|---|---|---|
| `08faf0fb9004` | `code-eval` | P0 | medium | real, not a vuln | exec() is genuinely present, but inside a private test-suite stub class that implements a sandbox-provider protocol so unit tests can run code without a real sandbox. It is never imported, exported, or registered by library code. |
| `48ea405cdad4` | `code-eval` | P0 | high | real, not a vuln | exec() of a caller-supplied string is the declared purpose of an opt-in code-execution mode off by default; the string is the feature's documented input, not smuggled data. The restricted namespace is thin, but the sink is by design. |
| `f444598a52d9` | `code-eval` | P0 | medium | real, not a vuln | Same construct as the sibling test module: exec() lives in a duplicated private test-only sandbox stub used to execute the code snippets a test itself authored. No production entry point constructs it and no external input reaches it. |
| `4daab31b00b0` | `codegen-injection` | P1 | medium | real defect | Caller-supplied names are interpolated raw into single-quoted literals of generated infrastructure source, and the model layer validates only that they are strings, so a name containing a quote breaks out into deployable code. |
| `9d95801c8b1b` | `codegen-injection` | P1 | medium | real defect | _Withheld._ This finding has not been reported to its maintainer; the mechanism is not described here. |
| `12af563eb52b` | `hardcoded-secret` | P1 | medium | false positive | Same pattern as the sibling script: the flagged string is a mirrored global-property-name constant used to check the served HTML, not a credential value. |
| `1b9d4b5ba945` | `hardcoded-secret` | P1 | medium | false positive | The matched value is a public OAuth token-endpoint URL constant, explicitly annotated in-line as not a password, and used only as an HTTP request target. |
| `1df48ecad44e` | `hardcoded-secret` | P1 | medium | real, not a vuln | A real literal is assigned, but it is the same publishable 'phc_' analytics ingest project key used by the sibling implementation in another language; such keys are intended to be embedded in shipped client code and are write-only. |
| `20d5aa6d0b18` | `hardcoded-secret` | P1 | low | false positive | Same pattern: a keychain field-name key for an install-level IdP client secret, not the secret value itself. |
| `231a54ce2b88` | `hardcoded-secret` | P1 | medium | false positive | The matched value is a write-only analytics ingest key, explicitly documented in an adjacent comment as public and read-incapable, not a confidential credential. |
| `2baeb7e4d080` | `hardcoded-secret` | P1 | medium | false positive | The matched literal is a public protocol version marker prepended to a presigned-URL token, not a secret value; it carries no entropy and is required verbatim by the wire format. |
| `399772046f7e` | `hardcoded-secret` | P1 | medium | false positive | The matched value is a fixed URL path suffix for a Data Center OAuth token endpoint, marked noqa as a non-secret, and only ever concatenated onto a base URL to build a request target. |
| `59873c1dcfcb` | `hardcoded-secret` | P1 | medium | false positive | The flagged string is the name of a global window property the backend injects so the browser can recover a token; it is an identifier for a mechanism, not the credential value. |
| `628c20ec4dae` | `hardcoded-secret` | P1 | medium | real, not a vuln | A real literal is assigned, but it is a public write-only browser analytics key designed to ship to every visitor's page; an inline comment documents that the paired secret key must never reach the browser. |
| `73099d5dc14d` | `hardcoded-secret` | P1 | low | false positive | The flagged value is a standards-defined URN naming an OAuth token-exchange subject-token type, used to build request bodies; it is a protocol constant, not a credential. |
| `73dc76208465` | `hardcoded-secret` | P1 | low | false positive | The match is an enumeration member naming a password-based connection method; the literal is the enum's symbolic value used as part of a connection-cache key, not a stored credential. |
| `838ebec9bcb7` | `hardcoded-secret` | P1 | low | false positive | The flagged string is a dash-joined field-name key used to look up an entry in the OS keychain (per file header), not the secret value; the real secret is stored separately at runtime. |
| `96f91c90e634` | `hardcoded-secret` | P1 | medium | false positive | The flagged string is the NAME of an environment variable that the code later reads a token from, not a secret value itself; it configures which env var to check. |
| `a23a6c292ee0` | `hardcoded-secret` | P1 | low | real, not a vuln | A short self-descriptive literal is assigned to a local variable and passed as auth-token env config to boot an ephemeral local verification server spawned by this same script; it is a throwaway test value with no external system to authenticate against. |
| `ae0af860cba9` | `hardcoded-secret` | P1 | medium | false positive | The flagged string is a plain-script mirror of a shared global-property-name constant (per the adjacent comment), used to check the served page for that global; it is an identifier, not a secret. |
| `bcdf48212488` | `hardcoded-secret` | P1 | low | real, not a vuln | Same pattern as the sibling smoke script: a short self-descriptive literal token used only to boot and authenticate a locally spawned prod-web smoke-test server, not a real credential. |
| `be1f9e228771` | `hardcoded-secret` | P1 | medium | real, not a vuln | A real literal is assigned, but it is a product-analytics write-only ingest project key of the vendor's publishable 'phc_' form, which is designed to ship inside distributed client SDKs; it grants event submission, not data access. |
| `d168337b8bcb` | `hardcoded-secret` | P1 | low | false positive | The flagged code is a template literal that computes a fresh pseudo-random value at call time (timestamp + Math.random), with an explicit 'test_access_token' prefix; there is no static secret literal at this line. |
| `d810eb9f8361` | `hardcoded-secret` | P1 | low | false positive | Same pattern: a standards-defined URN naming an ID-JAG token type for OAuth token exchange, not a credential value. |
| `da3039c5e503` | `hardcoded-secret` | P1 | medium | false positive | The value is explicitly a placeholder sentinel assigned in an exception handler when token acquisition fails, so the finding's core premise -- that the literal is non-placeholder -- is factually wrong. |
| `e3447670b764` | `hardcoded-secret` | P1 | medium | real, not a vuln | A real literal is assigned to a constant named TOKEN, but it is the vendor's publishable 'phc_' analytics ingest project key paired with a public event endpoint, intended to ship in distributed packages and limited to event submission. |
| `e7fa49321381` | `hardcoded-secret` | P1 | low | false positive | The match is an enumeration member naming an authentication method, not a credential: the flagged name is the enum member and the literal is its symbolic value used as a dictionary key for connection lookup. |
| `eac6ec325417` | `hardcoded-secret` | P1 | low | real, not a vuln | A short self-descriptive literal token is used only to authenticate a locally spawned headless-browser smoke-test server started by this same script; it is a throwaway test value, not a credential for any external system. |
| `efd7f424025f` | `hardcoded-secret` | P1 | low | false positive | The match is an error-classification enum member whose value is a lowercase category string; it is a taxonomy label consumed by error handling, never a credential. |
| `f3417ae8c15b` | `hardcoded-secret` | P1 | medium | false positive | The matched value is an OAuth token-exchange endpoint URL, not a credential. The rule fired on the substring 'TOKEN' in a module-level endpoint constant name sitting among three sibling endpoint URLs. |
| `f8345b06c70d` | `hardcoded-secret` | P1 | medium | false positive | The matched value is a fixed ASCII placeholder token used to shield escaped pipe characters through a markdown round-trip parser, not a credential of any kind. |
| `2fe8da8bd3cc` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Force-push is present but is the required companion to the preceding hard reset of a disposable prerelease branch, inside the same triply-conditioned release step; no branch carrying unique history is targeted. |
| `45067dd5c8cb` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Hard reset is present but is a release-automation step that deliberately rebases a prerelease branch onto the just-published stable branch, and the step is conditioned on branch, prerelease state and a should_publish flag. |
| `50b8c38a8706` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | rm -rf targets a fixed, script-created temp download directory as post-install cleanup after a successful Node.js install check, not a caller-influenced path or an exposed tool sink. |
| `5f5dbf49015e` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Recursive delete is present but is an EXIT-trap cleanup of a directory the same script created one line earlier via mktemp -d, in a documented example script; the deleted path can only be the script's own scratch directory. |
| `73affa071132` | `job-destructive-no-confirm` | P1 | medium | false positive | Two factual errors: the operand is a directory the script created one line earlier via mktemp -d, so nothing pre-existing can be destroyed; and the file does carry an env-gated early exit, which the rule said was absent. |
| `75789e817cae` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Same fixed-path lock cleanup in another CI job. Present as described but not a meaningful hazard: literal paths, ephemeral runner filesystem, no untrusted value in the command line. |
| `ae83270daea1` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Force-push is present but targets a dedicated read-only mirror repository whose content is regenerated wholesale each run; overwriting its history is the documented contract, and the step no-ops when the staged diff is empty. |
| `b0e86d424556` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Same fixed-path lock cleanup in a third CI job. The construct is real but confined to two literal lock directories on a disposable runner, with no dry-run or approval step being applicable. |
| `d79f5dbbf196` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Recursive delete is present but is test-harness cleanup of a scaffolded fixture directory whose name is derived from the test case label, executed with the working directory already changed into a per-run temp directory. |
| `d79f5dbbf196-2` | `job-destructive-no-confirm` | P1 | medium | false positive | The claim that no env-gated opt-out exists anywhere in the file is factually wrong: the delete sits inside an environment-variable conditional in the immediately enclosing control flow, and the target is a per-process temp path. |
| `df1d597420aa` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Identical CI housekeeping construct: a fixed-path stale-lock cleanup with no variable expansion, running on a throwaway CI runner before an agent step. No caller-influenced input reaches the path arguments. |
| `e02f0c99db35` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | The recursive delete is present and ungated, but its operands are two hardcoded lock-file paths with no interpolation, on an ephemeral CI runner. A confirmation prompt is impossible in a non-interactive job. |
| `e6d10d3ef379` | `job-destructive-no-confirm` | P1 | medium | false positive | Polarity is inverted and a guard governs the call: the recursive delete is the security-cleanup step that wipes an ephemeral signing-key home on a throwaway runner, and it only runs when that variable is set and the path is a directory. |
| `f53b81a4eb49` | `job-destructive-no-confirm` | P1 | medium | real, not a vuln | Recursive delete is present but runs in CI against a freshly cloned throwaway checkout under /tmp, scoped by an explicit '! -name .git' filter, immediately before an rsync repopulates it. Wiping that directory is the job's stated function. |
| `5a3055e2114a` | `network-exposure` | P1 | medium | real, not a vuln | listen() genuinely omits a host arg (defaults to all interfaces) and has no auth, but this file is an explicit reference/test HTTP entrypoint for a demo MCP server meant for local testing against a reference MCP client, not a hardened production surface. |
| `abd30096eda4` | `network-exposure` | P1 | medium | real, not a vuln | listen() genuinely omits a host arg (defaults to all interfaces) and has no auth, but this file is the same demo/reference MCP HTTP transport meant for local testing against a reference MCP client, not a production service. |
| `552285a9d2d5` | `secret-leak-via-tool-response` | P1 | high | false positive | Polarity is inverted: the field carries a stringified presence boolean, not a credential value â€” exactly the mitigation the rule recommends. The match is on the field name, not on any secret material. |
| `1255b0adb0b4` | `tool-scope-creep` | P1 | high | false positive | The claim that no check governs the deletion is factually wrong: an explicit path guard raises before the unlink, confining the target to one directory. It is also defined inside a test fixture over a temp dir. |
| `12c6086a574c` | `tool-scope-creep` | P1 | high | false positive | The tool is declared read-only in its own annotations and its body only POSTs a natural-language query to a suggestion endpoint and returns candidate command strings; nothing is executed and no state changes. |
| `141cb85df9d3` | `tool-scope-creep` | P1 | high | false positive | The same file contains a default-OFF write opt-in that forces read-only query mode, contradicting the finding's premise, and the flagged tool only establishes and caches a connection instead of performing a mutating operation. |
| `46c639bc893b` | `tool-scope-creep` | P1 | high | real, not a vuln | The tool does create a remote resource and the package carries no write gate, but resource creation is its advertised purpose and the only privilege boundary is the operator's own cloud credentials. |
| `55e662ceb4ee` | `tool-scope-creep` | P1 | high | false positive | The claim that the file shows no write opt-in is factually wrong: the same file defines a default-OFF write flag that puts query execution in read-only mode, and this tool only opens and caches a connection rather than mutating data. |
| `63687e5b47c0` | `tool-scope-creep` | P1 | high | false positive | The tool only calls describe/get-style read APIs and formats a diagnostic report string; it performs no create, update or delete, so the claim that a mutating sink is reachable from its body is wrong. |
| `7b75ebcf8f84` | `tool-scope-creep` | P1 | high | false positive | The function is a one-line pass-through to the same read-only documentation proxy; it changes no state locally or remotely, so the premise that a dangerous sink is reachable from its body is factually wrong. |
| `9a3bb66d7e79` | `tool-scope-creep` | P1 | high | false positive | The function is a documentation search: it assembles a query body and POSTs it to a search API, returning ranked results. There is no mutating or otherwise dangerous sink anywhere in the body. |
| `a88a3b7624fe` | `tool-scope-creep` | P1 | high | real, not a vuln | A genuinely ungated pass-through that can invoke any operation of one service API, including mutating ones, but arbitrary-operation invocation is the tool's documented purpose and its blast radius is bounded by the operator's credentials. |
| `bac232e804cc` | `tool-scope-creep` | P1 | high | false positive | The function is not mutating: it forwards a URL plus paging offsets to a read-only documentation proxy and returns the fetched text. No state-changing sink is reachable from its body. |
| `be2b16d1b852` | `tool-scope-creep` | P1 | high | real, not a vuln | The tool genuinely mutates state (starts a local database emulator, creates tables, writes files) with no gate, but that is the documented purpose of a validation harness and effects stay local to the caller's workspace. |
| `c99b35a64a08` | `tool-scope-creep` | P1 | high | false positive | The function is not mutating: it builds a params dict and forwards it to a read-only documentation-search proxy over HTTP. No dangerous or state-changing sink exists in its body or in the helper it calls. |
| `ccd2df0c48d6` | `tool-scope-creep` | P1 | high | false positive | A default-OFF write flag exists in the same file and gates all query execution to read-only, so the 'no env-flag opt-in anywhere in the file' premise fails; the flagged tool only creates and caches a connection. |
| `e6115003edc2` | `tool-scope-creep` | P1 | high | real, not a vuln | The ungated outbound side effect is real, but this is a documentation example whose whole purpose is demonstrating it; the recipient is pinned to the operator's own number from local env settings. |
| `ef3a908da93f` | `tool-scope-creep` | P1 | high | false positive | The tool is not mutating and reaches no dangerous sink: it takes zero parameters and returns a read-only telemetry snapshot. The only state change is appending to a bounded in-process list used as a chart history buffer. |
| `f030598bea49` | `tool-scope-creep` | P1 | high | false positive | A default-deny gate governs the sink in the immediate control flow: the very first statement of the tool returns an 'operation not permitted' string when the server is in read-only mode, before any delete is issued. |
| `fe6e259c1344` | `tool-scope-creep` | P1 | high | real, not a vuln | The mutating mouse-move/drag tool genuinely has no permission gate in this file, but the entire tool suite is ungated by the same design, matching the project's documented no-sandboxing operating model. |
| `2441dbbaa52a` | `tracked-secret-file` | P1 | high | false positive | The finding is filename-convention only: the tracked file holds no credential at all, just a localhost dev endpoint URL, a dev-server port number and two comment lines pointing at an untracked .local override for real values. |

## Limits of this record

- It is a **single pass by one reader**. It has not been independently
  re-audited, and it should not be cited as a measured false-positive rate.
- 53 of the 66 verdicts were recorded at high self-confidence and 13 at
  medium; none at low. The medium calls are concentrated in
  `tool-scope-creep`, where "is this the tool's advertised purpose?" is a
  judgement about intent rather than a fact about the code.
- One `codegen-injection` row is withheld. It is a real defect that has not
  been reported to its maintainer, and naming the mechanism here would make
  this document a finding aid for an unpatched bug.
- The full record, including the repository, path and the evidence read for
  each verdict, is retained locally in `ecoscan-artifacts/audit-66.json`.
  That directory is gitignored by the same disclosure rail that keeps target
  names out of this tree, so it is not published here.
