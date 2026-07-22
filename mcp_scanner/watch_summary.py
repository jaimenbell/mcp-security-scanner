"""Counts-only watch summary -- the ONLY payload the Managed MCP Watch
Action is allowed to transmit off a client machine.

Egress contract (counts-only allowlist, opt-in, off by default):

  The payload contains counts and identity metadata ONLY:
  repo name, commit SHA, scanner version, timestamp, files-scanned count,
  total findings, severity histogram, clean-bill boolean.

  It NEVER contains: file paths, code snippets, finding titles, finding
  detail, remediation text, or the local scan target path.

The builder works by ALLOWLIST extraction -- it copies nothing from the
scan result except explicitly named scalar counts. Adding any new field
requires adding it to ALLOWED_KEYS, which the egress test suite
(tests/test_watch_summary.py) locks down.

CLI (used by the composite Action's optional webhook step):

    python -m mcp_scanner.watch_summary \
        --json-file scan.json --repo owner/name --commit <sha>

Prints the JSON payload to stdout. It performs NO network I/O itself;
transmission (and whether it happens at all) is the Action's explicitly
opt-in webhook step.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__

# The complete set of keys a counts payload may carry. The egress tests
# assert payload keys == this set, so any drive-by field addition fails CI.
ALLOWED_KEYS = frozenset({
    "repo",
    "commit",
    "scanner_version",
    "generated_at",
    "files_scanned",
    "total_findings",
    "counts_by_severity",
    "clean_bill",
})


def build_counts_payload(scan_dict: dict, repo: str, commit: str) -> dict:
    """Build the counts-only summary from a ScanResult.to_dict() dict.

    Only scalar counts are copied out of the scan; the findings list, the
    local target path, and every prose field are deliberately never read
    into the payload.
    """
    counts = scan_dict.get("counts_by_severity", {})
    payload = {
        "repo": repo,
        "commit": commit,
        "scanner_version": __version__,
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "files_scanned": int(scan_dict.get("files_scanned", 0)),
        "total_findings": len(scan_dict.get("findings", [])),
        "counts_by_severity": {
            sev: int(counts.get(sev, 0)) for sev in ("P0", "P1", "P2", "P3")
        },
        "clean_bill": bool(scan_dict.get("clean_bill", False)),
    }
    assert set(payload.keys()) == ALLOWED_KEYS  # belt-and-suspenders
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m mcp_scanner.watch_summary",
        description="Build the counts-only watch summary payload from a "
                    "`mcp-scan --json` output file. Prints JSON to stdout; "
                    "performs no network I/O.",
    )
    parser.add_argument("--json-file", required=True,
                        help="path to a `mcp-scan <path> --json` output file")
    parser.add_argument("--repo", required=True,
                        help="repo identifier, e.g. $GITHUB_REPOSITORY")
    parser.add_argument("--commit", required=True,
                        help="commit SHA, e.g. $GITHUB_SHA")
    args = parser.parse_args(argv)

    try:
        # utf-8-sig tolerates the BOM that Windows-runner shells commonly
        # prepend (PowerShell Out-File / redirection); plain utf-8 files
        # are unaffected.
        with open(args.json_file, encoding="utf-8-sig") as fh:
            scan_dict = json.load(fh)
    except OSError as e:
        print(f"error: cannot read {args.json_file}: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: {args.json_file} is not valid JSON: {e}",
              file=sys.stderr)
        return 1

    print(json.dumps(
        build_counts_payload(scan_dict, repo=args.repo, commit=args.commit),
        indent=2,
    ))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
