"""The killer dogfood proof: run the scanner against the fleet's own MCP servers.

Requirement from the product spec:
  (a) it flags the mcp-factory codegen-injection class the fleet audit found, and
  (b) it gives the audited-clean servers a clean bill (no P0/P1).

The fleet root is never hardcoded — these tests read it from the
MCP_SCANNER_FLEET_ROOT env var (same as the CLI). They skip gracefully
whenever that var is unset or the fleet repos aren't present (e.g. CI on
another machine, or any environment other than the operator's own).
"""

import os

import pytest

from mcp_scanner.cli import FLEET_ROOT_ENV_VAR, get_fleet_root, run_self_audit
from mcp_scanner.scanner import scan_repo

CLEAN_SERVERS = ["github-mcp", "bus-mcp", "desktop-mcp", "rag-mcp", "discord-mcp"]


def _fleet_root_or_none():
    raw = os.environ.get(FLEET_ROOT_ENV_VAR)
    return get_fleet_root() if raw else None


def _have_fleet():
    root = _fleet_root_or_none()
    return root is not None and (root / "mcp-factory").exists()


# Applied per-test (not module-wide) so test_self_audit_errors_clearly_without_env_var
# below — which specifically exercises the unset-env-var path — still runs even when
# MCP_SCANNER_FLEET_ROOT is unset.
requires_fleet = pytest.mark.skipif(
    not _have_fleet(),
    reason=f"{FLEET_ROOT_ENV_VAR} unset or fleet MCP servers not present",
)


@requires_fleet
def test_mcp_factory_scans_clean_after_codegen_fix():
    # Fleet drift (reconciled 2026-07-21): the mcp-factory codegen-injection
    # finding the original manual audit surfaced was GENUINELY FIXED upstream,
    # so the live repo now scans clean. The scanner's codegen-injection
    # detection itself is proven drift-free against tests/fixtures/vuln_codegen
    # (see test_codegen_injection.py) -- this test no longer asserts a live vuln
    # that no longer exists; it pins current fleet reality: mcp-factory clean.
    fleet_root = get_fleet_root()
    r = scan_repo(str(fleet_root / "mcp-factory"))
    highs = [f for f in r.findings if f.severity.value in ("P0", "P1")]
    assert r.clean_bill, (
        "mcp-factory should scan clean post-fix, got P0/P1: "
        + "; ".join(f"{f.severity.value} {f.vuln_class} {f.file}:{f.line}" for f in highs)
    )


@requires_fleet
@pytest.mark.parametrize("name", CLEAN_SERVERS)
def test_clean_servers_get_clean_bill(name):
    fleet_root = get_fleet_root()
    target = fleet_root / name
    if not target.exists():
        pytest.skip(f"{name} not present")
    r = scan_repo(str(target))
    highs = [f for f in r.findings if f.severity.value in ("P0", "P1")]
    assert r.clean_bill, (
        f"{name} should get a clean bill, got P0/P1: "
        + "; ".join(f"{f.severity.value} {f.vuln_class} {f.file}:{f.line}" for f in highs)
    )


@requires_fleet
def test_self_audit_shape():
    results = run_self_audit()
    assert len(results) >= 1
    by_name = {r.target.replace("\\", "/").rsplit("/", 1)[-1]: r for r in results}
    # Shape check: every self-audit result carries a target and a findings list
    # with valid grades. (This used to assert mcp-factory was non-clean or had a
    # codegen finding; that vuln was fixed upstream -- fleet drift reconciled
    # 2026-07-21 -- so the shape, not a specific stale finding, is what's pinned.)
    for r in results:
        assert r.target
        assert isinstance(r.findings, list)
    if "mcp-factory" in by_name:
        # Current reality: mcp-factory scans clean post-fix.
        assert by_name["mcp-factory"].clean_bill


def test_self_audit_errors_clearly_without_env_var(monkeypatch):
    monkeypatch.delenv(FLEET_ROOT_ENV_VAR, raising=False)
    with pytest.raises(RuntimeError, match=FLEET_ROOT_ENV_VAR):
        run_self_audit()
