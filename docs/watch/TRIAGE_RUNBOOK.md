# MCP Watch Triage Runbook (operator-facing)

Purpose: produce one client's monthly digest in **30 minutes or less**,
honestly, from a per-client baseline. This is the paid deliverable; the
time cap is a design constraint, not a stretch goal (spec gate G6).

## Per-client state you keep (metadata only)

One folder per client, operator-side, containing:

- `baseline.json` -- the suppression list. One entry per triaged finding
  the client should never be nagged about again:

  ```json
  [
    {
      "fingerprint": "codegen-injection|server/tools.py|register_tool",
      "verdict": "false-positive",
      "note": "template var is a hardcoded enum, not tool input",
      "triaged": "2026-07-01"
    }
  ]
  ```

  Fingerprint = `vuln_class|file|title` from the client-shared report.
  Use the finding's file path only if the client shared it (they choose
  what to share -- see the privacy table in ONBOARDING.md). If you hold
  counts only, the baseline holds counts-level notes instead.
- `digests/` -- sent digests, one per month.
- `notes.md` -- pin version, webhook on/off, contact, standing decisions
  ("client accepts P3 secret-log findings in tests/", etc).

Never store client source code, ever. Snippets the client pasted during a
triage conversation may be quoted in `baseline.json` notes ONLY if needed
to make the suppression auditable, and should be trimmed to the minimum.

## The 30-minute clock

| Step | Budget | What |
|---|---|---|
| 1. Collect | 5 min | Pull this month's inputs: the client-shared report artifact (ask for the latest red/green run's `mcp-scan-report` artifact if they have not forwarded one), or the counts-webhook history if that is all you hold. Note scans-run count. |
| 2. Diff vs baseline | 5 min | List findings in the new report whose fingerprint is NOT in `baseline.json` (net-new), and baseline entries absent from the report (resolved). No report shared this month = counts-only digest; say so in the Coverage note, do not guess. |
| 3. Triage net-new | 10 min | For each net-new finding: read its detail/remediation/confidence in the report; verdict = REAL / FALSE POSITIVE / ACCEPTED RISK. Unsure after 3 minutes on one finding = verdict "REAL -- needs a look", schedule a 15-min call; do NOT burn the clock going spelunking. |
| 4. Update baseline | 3 min | Add false-positive + accepted-risk entries with note + date. Remove resolved entries. |

A `reachable: unknown` finding is not automatically "needs a look" --
`unknown` means the scanner couldn't decide, not that a human can't. Check
the finding's actual callers first: if the only call path back to it is
operator-supplied input (CLI argv, a config file, an admin script) with
zero MCP-tool-registered callers reaching it, that's a decidable false
positive, not an unsure verdict -- baseline it and move on (seen live:
`rag-mcp/lock.py:144`, 2026-07-22 dogfood, one grep + two reads).
| 5. Write digest | 7 min | Fill `DIGEST_TEMPLATE.md` top to bottom. Sections with nothing to report get one honest line, not filler. |

Hard stop at 30 minutes: if the clock runs out, send the digest with what
is done and an explicit "still reviewing finding #N, follow-up by {date}"
line. An honest partial beats a late perfect.

## Escalation (outside the monthly cadence)

- **P0 verdict REAL at any time:** do not wait for the digest. Same-day
  short email: what it is, why it is real, the remediation. This is the
  only pager-shaped obligation, and it is triggered by YOUR triage, not by
  their CI (their CI failing is their build gate doing its job).
- **False-positive pattern seen at 2+ clients:** open an issue on the
  scanner repo; fix the rule in the next release instead of baselining it
  per-client forever.

## Monthly release-cadence duties (not per-client)

- Cut a scanner release tag when rules changed this month; mention it in
  every digest (section 5) so clients know whether to bump their pin.
- No release this month is fine -- say so in the digests.

## Capacity math (when to stop taking watch clients)

At <= 30 min/client/month plus ~1 h/month shared release duty, ten clients
is ~6 h/month. If real triage time creeps past 30 min/client for two
consecutive months, either the rules need fixing (false-positive burden)
or the client's repo needs a paid deep review (Tier 1/3) -- say which,
do not silently absorb it.
