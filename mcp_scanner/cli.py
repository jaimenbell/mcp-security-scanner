"""Command-line entry point.

    mcp-scan <path>                 scan one repo, print a markdown report
    mcp-scan <path> --json          emit JSON instead
    mcp-scan --self-audit           scan the operator's 6 fleet MCP servers
                                    (the dogfood trust-signal proof)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .scanner import scan_repo
from .reporting import render_markdown, render_json, render_summary_line
from .models import ScanResult

# The operator's real MCP servers. mcp-factory is the known-vulnerable target
# (codegen-injection class); the other five were audited clean.
#
# FLEET_ROOT is intentionally NOT hardcoded — it's read from an env var so
# this repo carries no personal directory structure. Set it locally, e.g.
# (PowerShell):  $env:MCP_SCANNER_FLEET_ROOT = "C:\Users\you\projects"
# (bash):        export MCP_SCANNER_FLEET_ROOT=/path/to/your/projects
FLEET_ROOT_ENV_VAR = "MCP_SCANNER_FLEET_ROOT"
FLEET_SERVERS = [
    "mcp-factory",   # KNOWN: codegen-injection surface (should flag)
    "github-mcp",    # clean
    "bus-mcp",       # clean
    "desktop-mcp",   # clean
    "rag-mcp",       # clean
    "discord-mcp",   # clean
]


def get_fleet_root() -> Path:
    """Resolve the fleet root from the environment. Raises if unset."""
    raw = os.environ.get(FLEET_ROOT_ENV_VAR)
    if not raw:
        raise RuntimeError(
            f"--self-audit requires the {FLEET_ROOT_ENV_VAR} environment variable "
            "to point at the directory containing your MCP server repos "
            f"(e.g. {FLEET_ROOT_ENV_VAR}=/path/to/projects). This var has no "
            "default so the repo carries no personal path."
        )
    return Path(raw)


def _self_audit_targets() -> list[Path]:
    fleet_root = get_fleet_root()
    return [fleet_root / name for name in FLEET_SERVERS]


def run_self_audit(as_json: bool = False) -> list[ScanResult]:
    results: list[ScanResult] = []
    for target in _self_audit_targets():
        if not target.exists():
            continue
        results.append(scan_repo(str(target)))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="Static security scanner for MCP servers.",
    )
    parser.add_argument("path", nargs="?", help="path to an MCP server repo")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--self-audit", action="store_true",
                        help="scan the fleet's own MCP servers (dogfood proof)")
    parser.add_argument("--fail-on", choices=["P0", "P1", "P2", "P3"], default=None,
                        help="exit non-zero if any finding at/above this severity")
    args = parser.parse_args(argv)

    if args.self_audit:
        try:
            results = run_self_audit()
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if args.json:
            import json
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print("MCP Fleet Self-Audit\n" + "=" * 60)
            for r in results:
                print(render_summary_line(r))
            print("=" * 60)
            flagged = [r for r in results if not r.clean_bill]
            clean = [r for r in results if r.clean_bill]
            print(f"{len(flagged)} server(s) with P0/P1 findings, "
                  f"{len(clean)} clean bill.")
        return _exit_code(results, args.fail_on)

    if not args.path:
        parser.error("provide a path to scan, or use --self-audit")

    result = scan_repo(args.path)
    print(render_json(result) if args.json else render_markdown(result))
    return _exit_code([result], args.fail_on)


def _exit_code(results: list[ScanResult], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}[fail_on]
    for r in results:
        for f in r.findings:
            if f.severity.rank <= rank:
                return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
