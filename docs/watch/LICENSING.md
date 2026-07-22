# What is free, what you pay for (plain language)

This page exists so there is never a surprise about what your subscription
buys. Spec gate G7: no implication, ever, that the open-source binary is
being sold back to you.

## Free and open source (MIT), forever

Everything currently in the public repository
`github.com/jaimenbell/mcp-security-scanner`:

- the scanner engine: all seven detector families, the reachability pass,
  the taint pass;
- the CLI (`mcp-scan`), including `--fail-on` severity gating, `--json`,
  and the full `--client-report` output;
- the GitHub Action (`action/`) and the pre-commit hook
  (`.pre-commit-hooks.yaml`).

You can clone it, run it in your CI, and gate your builds with it for $0,
forever, with no subscription. That is what MIT means, and we will say so
in every sales conversation.

## What the Managed MCP Watch subscription buys

Things a public repository cannot give you:

1. **Human triage against your baseline.** Every net-new finding gets a
   human verdict (real / false positive / accepted risk) once a month, so
   your team never chases noise. False positives are suppressed in your
   baseline and never nag you again.
2. **Rule freshness on a stated cadence.** The MCP threat landscape moves.
   Rule updates ship as versioned releases; the digest tells you when a
   bump is worth it. A one-time clone goes stale; the subscription does
   not.
3. **A human to ask.** A confusing finding gets a plain-language answer
   from the person who wrote the rules.

## The premium detector pack (planned, not yet shipped)

A separate, commercially licensed (NOT MIT) detector pack with rules
beyond the public core is planned as a follow-on to the watch service.
When it ships: subscribers get access while subscribed; access ends when
the subscription does; the public core keeps working regardless. Until it
ships, nothing you install is under any license other than MIT, and this
page will be updated when that changes.

## The honest one-liner

"The scanner is free and open -- clone it and run it yourself anytime. The
subscription buys you a human who triages every net-new finding so you
never chase a false alarm, and a ruleset kept current as MCP threats
evolve."
