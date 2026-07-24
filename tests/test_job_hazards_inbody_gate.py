"""FP-wave-2 regression tests for the 2026-07-23 public-MCP ecosystem-scan
triage backlog:

  * Class #1 -- an MCP server/wrapper that implements its OWN destructive-action
    confirmation gate inline (a real control-flow gate on a boolean param named
    force/yes/confirm/proceed, not just the SDK's -Confirm / --dry-run flag)
    should be recognised as an equivalent safety control and demote the
    job-destructive-no-confirm finding.

  * Class #2 -- the destructiveHint doctrine: a target declaring
    ``destructiveHint: true`` is a SELF-declaration, informational only. It may
    at most appear as context on a finding; it must NEVER suppress or downgrade
    the severity/confidence/visibility of a genuine unguarded destructive call.
"""

from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import JobHazardsDetector
from mcp_scanner.models import Severity, Confidence


def _run(fixtures_dir, name):
    return scan_repo(str(fixtures_dir / name), [JobHazardsDetector()])


def _destructive(r):
    return [f for f in r.findings if f.vuln_class == "job-destructive-no-confirm"]


def test_inbody_force_gate_suppresses(fixtures_dir):
    r = _run(fixtures_dir, "inbody_gate_force")
    hits = _destructive(r)
    assert hits == [], [f"{f.file}:{f.line} {f.title}" for f in hits]


def test_bare_areyousure_phrase_does_not_suppress(fixtures_dir):
    """FP-wave-2 adjudication regression (2026-07-23): a bare 'are you sure'
    display string / comment, bound to no param and no control-flow exit, must
    NOT be mistaken for a confirm-before-destroy gate. A genuinely unguarded
    destructive call elsewhere in the same file must still be flagged."""
    r = _run(fixtures_dir, "inbody_gate_bare_phrase")
    hits = _destructive(r)
    assert any(f.file.endswith("deploy.sh") for f in hits), \
        [f"{f.file}:{f.line} {f.title}" for f in hits]


def test_param_present_without_gate_still_flags(fixtures_dir):
    r = _run(fixtures_dir, "inbody_gate_paramonly")
    hits = _destructive(r)
    assert any(f.file.endswith("cleanup.ps1") for f in hits), \
        [f"{f.file}:{f.line} {f.title}" for f in hits]


def test_destructive_hint_does_not_suppress_or_downgrade(fixtures_dir):
    r = _run(fixtures_dir, "destructive_hint_unguarded")
    hits = _destructive(r)
    assert hits, "destructiveHint:true must not suppress a genuine unguarded destructive call"
    f = hits[0]
    assert f.severity == Severity.P1, f.severity
    assert f.confidence == Confidence.MEDIUM, f.confidence
    assert "destructiveHint" in f.detail, f.detail
