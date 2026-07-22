# Monthly MCP Watch Digest -- TEMPLATE

<!--
Operator instructions (delete before sending):
- Target fill time: <= 20 minutes using TRIAGE_RUNBOOK.md; the runbook's
  step timings map to the sections below.
- Every claim of "new" or "resolved" must come from diffing the client's
  latest shared report against the per-client baseline file -- never from
  memory.
- Counts come from the client's CI artifact (or their counts webhook if
  they enabled it). If you hold only counts, say so in Coverage.
-->

**Client:** {client name}
**Period:** {YYYY-MM}
**Scanner version in their pin:** {vX.Y.Z} (latest released: {vX.Y.Z})
**Baseline version:** {baseline file date/hash}
**Prepared by:** {operator}, {date}

---

## 1. TL;DR

{One to three sentences. Lead with the single most important thing:
"nothing new, ship with confidence" or "one real P1, fix is a one-liner,
details below." Never bury a P0/P1.}

## 2. Net-new findings this month (triaged)

{Only findings NOT in the baseline. One row per finding. If none: "None --
no new findings since last digest." and delete the table.}

| # | Severity | Class | Verdict | What it means for you |
|---|---|---|---|---|
| 1 | P1 | {vuln class} | REAL -- fix recommended | {one plain-English sentence + the remediation} |
| 2 | P3 | {vuln class} | FALSE POSITIVE -- baselined | {why it is noise; added to your baseline, will not nag again} |

Verdict legend: REAL (fix it) / FALSE POSITIVE (baselined) /
ACCEPTED RISK (you told us to accept it; baselined with a note).

## 3. Resolved since last month

{Findings present in the baseline that no longer appear. If none, say so.}

- {finding}: resolved by {commit/fix, if known}.

## 4. Baseline changes

- Added: {n} entries ({m} false positives, {k} accepted risks)
- Removed: {n} entries (resolved)
- Current baseline size: {n} suppressed findings

## 5. Rule updates this month

{What changed in the ruleset/scanner since their pinned tag, and whether
they should bump. If no release this month, say "No release this month;
your pin is current."}

- {vX.Y.Z}: {one line per relevant change}
- Recommended action: {bump pin to vX.Y.Z / stay put}

## 6. Trend

| Month | Scans run | P0 | P1 | P2 | P3 | Net-new | Resolved |
|---|---|---|---|---|---|---|---|
| {prev} | {n} | 0 | 0 | 2 | 3 | 1 | 0 |
| {this} | {n} | 0 | 0 | 2 | 2 | 0 | 1 |

## 7. Coverage note

{Honesty section. State what this digest is based on: e.g. "Based on the
report artifact you shared on {date} plus counts-webhook data from {n}
CI runs." If the client shared nothing this month: "No report was shared
this month; this digest is based on counts only -- severities and trend
are accurate, per-finding triage was not possible."}

## 8. Anything you should ask us

{Optional: one or two forward-looking notes -- an MCP threat pattern seen
in the wild this month, a config worth tightening. Keep it to two lines.
Delete if empty; no filler.}
