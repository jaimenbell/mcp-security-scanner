# Managed MCP Watch -- Client Onboarding

Welcome. This document gets your repository under watch in about ten
minutes. Nothing in this setup sends your source code anywhere: the scan
runs inside YOUR CI, on YOUR runners, and the full report lands in YOUR
artifact store.

## What you are getting

1. **A CI security gate.** Every push (and a weekly scheduled run) scans
   your MCP server for codegen injection, tool-parameter injection, auth
   posture gaps, and secret-handling issues. A P0/P1 finding fails the
   build.
2. **A monthly human-triaged digest.** A human (not a bot) reviews every
   net-new finding against your baseline and tells you which ones are real,
   which are noise, and what to do -- so you never chase a false alarm.
3. **Rule freshness.** The ruleset is updated as MCP threats evolve and
   shipped as versioned releases; you bump one pinned tag to pick them up.
4. **A human to ask.** If a finding is confusing, you email and a person
   answers.

The scanner itself is free and open source (MIT). You are paying for the
triage, the freshness, and the human -- see `LICENSING.md` in this folder
for the plain-language split.

## Privacy model (read this first)

| Data | Where it lives | Ever reaches us? |
|---|---|---|
| Your source code | Your CI runner only | **Never.** |
| Full findings report (file/line/snippets) | Your CI artifact store | Only if you choose to share it for triage. |
| Counts summary (N findings, severities, repo, commit) | Optional webhook | **Off by default.** Only if you enable it. Contains no code, no paths, no finding text. |
| Your credentials | -- | **Never held.** |

This is enforced in code, not just promised: the action's egress surface
is covered by automated tests that fail the scanner's own CI if any step
other than the opt-in counts webhook could transmit anything, or if the
counts payload ever contains source material.

## Step 1 -- Add the workflow (10 lines)

Create `.github/workflows/mcp-watch.yml`:

```yaml
name: MCP Watch
on:
  push:
    branches: [main]
  schedule: [{cron: "0 6 * * 1"}]
jobs:
  mcp-watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jaimenbell/mcp-security-scanner/action@b6627d37772987eff978ec6339087337ab36cc33  # v0.1.0 release commit -- swap in whatever SHA you're installing at
```

That is the whole integration. Scope `branches:` to your primary branch
(shown: `main` -- use `master` or whatever yours is). Pin the action to a
**full commit SHA**, not a tag -- that is the primary, supported pin today
(matches our own SHA-pinning posture; see Friction #3 in the dogfood notes
if you're curious why). The example above is the commit the `v0.1.0`
release corresponds to; re-pin to the SHA you actually want at install
time by checking the repo's commit history. Once we publish release tags
you can pin to a tag instead (e.g. `@v0.1.0`) for readability -- we'll
announce it in the monthly digest when that lands. Nothing auto-updates
underneath you either way.

### Adding Watch alongside an existing workflow

Most repos already have CI (a `ci.yml` or similar). `mcp-watch.yml` is a
separate, independent workflow file -- there's no job-name collision and
GitHub runs both without any wiring between them. The one thing to carry
over deliberately: scope the `on: push:` trigger to your primary branch
the same way your existing CI does (`branches: [main]` above, or
`[master]` if that's your convention) rather than leaving it unscoped.
An unscoped `on: push` fires on every push to every topic branch, not just
the branch your existing CI treats as canonical -- which burns more CI
minutes than most repos' convention would suggest and surprises people
expecting Watch to behave like their other checks.

### Action inputs (all optional)

| Input | Default | What it does |
|---|---|---|
| `scan-path` | `.` | Subdirectory to scan, if your MCP server is not at the repo root. |
| `fail-on` | `P1` | Fail the build at/above this severity (`P0`, `P1`, `P2`, `P3`). Empty string = report-only mode, never fails. |
| `client-name` | `the client` | Name printed on the report header. |
| `report-artifact-name` | `mcp-scan-report` | Name of the uploaded artifact in YOUR artifact store. |
| `counts-webhook-url` | empty (off) | Opt-in: POST a counts-only summary (no code, no paths, no finding text) to this URL after each scan. Leave empty to transmit nothing. **If you enable it, pass the URL via a repository secret** (`counts-webhook-url: ${{ secrets.MCP_WATCH_WEBHOOK }}`) — webhook URLs often embed access tokens, and a secret keeps the URL masked in workflow logs. |
| `python-version` | `3.11` | Python used to run the scanner. |

### Action outputs

| Output | Meaning |
|---|---|
| `report-path` | Runner-local path of the generated report (already uploaded as an artifact). |
| `clean-bill` | `true` when the scan found no P0/P1 findings. |

## Step 2 (optional) -- Local pre-commit gate

Catch findings before they ever reach CI. Add to your
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/jaimenbell/mcp-security-scanner
    rev: b6627d37772987eff978ec6339087337ab36cc33  # v0.1.0 release commit -- swap in whatever SHA you're installing at
    hooks:
      - id: mcp-scan
```

Same pinning note as Step 1: `rev:` takes a full commit SHA today (shown:
the `v0.1.0` release commit); once release tags are published, `rev:
v0.1.0` works too and we'll say so in the digest. The hook scans your
whole repo locally and blocks a commit that introduces a P0/P1 finding.
It runs entirely on your machine and transmits nothing.

## Step 3 (optional) -- Run the CLI yourself

The scanner installs cleanly from a pinned commit; no PyPI account, no
environment variables, no editable install:

```
pip install "git+https://github.com/jaimenbell/mcp-security-scanner@b6627d37772987eff978ec6339087337ab36cc33"  # v0.1.0 release commit -- re-pin to your target SHA
mcp-scan path/to/your/mcp-server --fail-on P1
```

Once release tags are published, `@v0.1.0` works too -- for now the SHA is
the supported pin.

Exit code 2 means a finding at/above the threshold; 0 means the gate
passed. Add `--client-report` for the full narrative report, `--json` for
machine-readable output.

## When the build goes red

1. Open the `mcp-scan-report` artifact on the failed run -- it explains
   each finding, its severity, its confidence, and a remediation.
2. If it is clearly real: fix it (the report tells you how) and push.
3. If you are not sure: forward the relevant finding (or the whole report,
   your call -- see the privacy table) and a human will triage it with you.
   Confirmed false positives go into your baseline so they never nag you
   again; the fix lands in a rule update when the pattern is wrong for
   everyone.

## The monthly digest

Once a month you receive a short, human-written digest: net-new findings
since last month (triaged: real vs noise), what was resolved, any rule-pack
updates worth bumping your pin for, and trend counts. The template is
`DIGEST_TEMPLATE.md` in this folder, so you know exactly what to expect.

## Support

Email with a finding ID or a report excerpt; you get a plain-language
answer, not a ticket number.
