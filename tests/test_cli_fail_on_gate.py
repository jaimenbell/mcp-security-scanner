"""Functional exit-code tests for the --fail-on severity gate.

This is the contract both the GitHub Action's gate step and the pre-commit
hook rely on (spec gates G1/G2/G3): exit 2 when a finding at/above the
threshold exists, exit 0 otherwise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_scanner.cli import main

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
