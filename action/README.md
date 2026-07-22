# Managed MCP Watch -- GitHub Action

Composite action that scans this repository's MCP server code with
[mcp-security-scanner](https://github.com/jaimenbell/mcp-security-scanner)
and fails the build on P0/P1 findings. Your source never leaves your
runner; the full report is uploaded to YOUR artifact store; the only
optional egress is a counts-only summary webhook that is OFF by default.

Minimal usage (pin to a release tag):

```yaml
name: MCP Watch
on:
  push:
  schedule: [{cron: "0 6 * * 1"}]
jobs:
  mcp-watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jaimenbell/mcp-security-scanner/action@v0.1.0
```

Full input/output reference, privacy model, and the local pre-commit
variant: see [docs/watch/ONBOARDING.md](../docs/watch/ONBOARDING.md).

The action's egress rules are enforced by the repo's own test suite:
`tests/test_watch_action.py` (structure: exactly one opt-in egress step)
and `tests/test_watch_summary.py` (payload: counts only, no source
material).
