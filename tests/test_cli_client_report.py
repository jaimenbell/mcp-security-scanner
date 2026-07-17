"""Tests for the CLI's --client-report wiring (Phase 0 report upgrade)."""
from __future__ import annotations

from mcp_scanner.cli import main


def test_client_report_flag_renders_eight_section_report(capsys):
    rc = main(["tests/fixtures/vuln_codegen", "--client-report",
               "--client-name", "Acme"])
    out = capsys.readouterr().out
    assert "# MCP Server Security Audit -- Acme" in out
    assert "## 6. Scope & method" in out
    assert rc == 0


def test_client_report_flag_default_client_name(capsys):
    rc = main(["tests/fixtures/clean_auth", "--client-report"])
    out = capsys.readouterr().out
    assert "# MCP Server Security Audit -- the client" in out
    assert rc == 0


def test_markdown_report_still_the_default_without_flag(capsys):
    """Backward-compat: omitting --client-report keeps the existing terse
    render_markdown() output (unchanged behavior for CI/plain use)."""
    rc = main(["tests/fixtures/clean_auth"])
    out = capsys.readouterr().out
    assert "# MCP Server Security Scan" in out
    assert "# MCP Server Security Audit" not in out
    assert rc == 0
