"""The killer dogfood proof: run the scanner against the fleet's own MCP servers.

Requirement from the product spec:
  (a) it flags the mcp-factory codegen-injection class the fleet audit found, and
  (b) it gives the audited-clean servers a clean bill (no P0/P1).

Skips gracefully if the fleet repos aren't present (CI on another machine).
"""

import pytest

from mcp_scanner.cli import FLEET_ROOT, run_self_audit
from mcp_scanner.scanner import scan_repo

CLEAN_SERVERS = ["github-mcp", "bus-mcp", "desktop-mcp", "rag-mcp", "discord-mcp"]


def _have_fleet():
    return (FLEET_ROOT / "mcp-factory").exists()


pytestmark = pytest.mark.skipif(not _have_fleet(), reason="fleet MCP servers not present")


def test_mcp_factory_flags_codegen_injection():
    r = scan_repo(str(FLEET_ROOT / "mcp-factory"))
    cg = [f for f in r.findings if f.vuln_class == "codegen-injection"]
    assert cg, "scanner must flag the mcp-factory codegen-injection class"


@pytest.mark.parametrize("name", CLEAN_SERVERS)
def test_clean_servers_get_clean_bill(name):
    target = FLEET_ROOT / name
    if not target.exists():
        pytest.skip(f"{name} not present")
    r = scan_repo(str(target))
    highs = [f for f in r.findings if f.severity.value in ("P0", "P1")]
    assert r.clean_bill, (
        f"{name} should get a clean bill, got P0/P1: "
        + "; ".join(f"{f.severity.value} {f.vuln_class} {f.file}:{f.line}" for f in highs)
    )


def test_self_audit_shape():
    results = run_self_audit()
    assert len(results) >= 1
    by_name = {r.target.replace("\\", "/").rsplit("/", 1)[-1]: r for r in results}
    if "mcp-factory" in by_name:
        assert not by_name["mcp-factory"].clean_bill or any(
            f.vuln_class == "codegen-injection" for f in by_name["mcp-factory"].findings
        )
