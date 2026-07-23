"""Functional exit-code tests for the --fail-on severity gate.

This is the contract both the GitHub Action's gate step and the pre-commit
hook rely on (spec gates G1/G2/G3): exit 2 when a finding at/above the
threshold exists, exit 0 otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scanner.cli import main, _exit_code
from mcp_scanner.models import Finding, Severity, Confidence, Reachability, ScanResult

FIXTURES = Path(__file__).parent / "fixtures"
VULN = str(FIXTURES / "vuln_codegen")
CLEAN = str(FIXTURES / "clean_codegen")


def test_vuln_fixture_fails_p1_gate(capsys):
    assert main([VULN, "--fail-on", "P1"]) == 2
    capsys.readouterr()


def test_clean_fixture_passes_p1_gate(capsys):
    assert main([CLEAN, "--fail-on", "P1"]) == 0
    capsys.readouterr()


def test_no_gate_means_exit_zero_even_on_findings(capsys):
    assert main([VULN]) == 0
    capsys.readouterr()


def test_p3_gate_catches_lower_severities_too(capsys):
    # Gate at P3 trips on ANY finding (P0..P3 all rank at/above P3).
    assert main([VULN, "--fail-on", "P3"]) == 2
    capsys.readouterr()


def test_gate_works_with_client_report_output(capsys):
    # The Action generates the client report and gates in separate
    # invocations, but gating + report in one call must also work.
    assert main([VULN, "--client-report", "--fail-on", "P1"]) == 2
    out = capsys.readouterr().out
    assert out  # report still printed


def test_gate_works_with_json_output(capsys):
    assert main([VULN, "--json", "--fail-on", "P1"]) == 2
    capsys.readouterr()


# --------------------------------------------------------------------- #
# 2026-07-22: reachability:cli-only is excluded from --fail-on by default
# (its only known caller is a non-tool entrypoint, never a registered MCP
# tool) -- --include-cli-only-in-gate opts back in.
# --------------------------------------------------------------------- #
def _cli_only_result(severity=Severity.P1):
    finding = Finding(
        vuln_class="param-injection",
        title="os.system invocation",
        severity=severity,
        confidence=Confidence.MEDIUM,
        file="lock.py",
        line=10,
        detail="test finding",
        remediation="n/a",
        reachability=Reachability.CLI_ONLY,
        reachability_evidence="called only from cli.py:35 _cmd_ingest",
    )
    return ScanResult(target="fake", findings=[finding], files_scanned=1)


def test_cli_only_excluded_from_gate_by_default():
    assert _exit_code([_cli_only_result()], "P1") == 0


def test_cli_only_included_with_explicit_flag():
    assert _exit_code([_cli_only_result()], "P1", include_cli_only=True) == 2


CLI_ONLY_ONLY = str(FIXTURES / "reachability_cli_gate_only")


def test_main_e2e_cli_only_finding_passes_gate_by_default(capsys):
    assert main([CLI_ONLY_ONLY, "--fail-on", "P1"]) == 0
    capsys.readouterr()


def test_main_e2e_cli_only_finding_fails_gate_with_flag(capsys):
    assert main([CLI_ONLY_ONLY, "--fail-on", "P1", "--include-cli-only-in-gate"]) == 2
    capsys.readouterr()


def test_uncalled_still_counts_toward_gate():
    # UNCALLED is not covered by the cli-only carve-out -- it still gates
    # by severity as before (dead code is a hygiene finding, not exempted).
    finding = Finding(
        vuln_class="param-injection", title="t", severity=Severity.P1,
        confidence=Confidence.MEDIUM, file="dead.py", line=1, detail="d",
        remediation="n/a", reachability=Reachability.UNCALLED,
    )
    result = ScanResult(target="fake", findings=[finding], files_scanned=1)
    assert _exit_code([result], "P1") == 2
