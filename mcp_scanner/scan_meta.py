"""Scanner-side scan metadata: version + canonical suite counts.

The client report's cover section states which scanner version (git SHA)
produced the scan and what the scanner's own canonical test count was at
that version -- READ from the scan JSON, never invented at render time. So
the scan embeds both here, at scan time.

- ``scanner_version()``: the scanner repo's own git short SHA (this file's
  parent checkout), falling back to the package ``__version__`` for a
  non-git install.
- ``suite_counts()``: the CI-gated test-count claim parsed from this repo's
  own README "## Tests" line -- the same anchored phrasing
  ``scripts/check_readme_counts.py`` verifies against junit.xml on every
  push, which is what makes it canonical rather than hand-typed. Returns
  ``None`` (embedded as JSON null) when no README/claim is present (e.g.
  an installed wheel), never a guess.

Both are cached per process; presentation-layer only.
"""
from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path

# Anchored to the same README phrasing scripts/check_readme_counts.py gates
# in CI ("# <total> tests (<passed> passing, <skipped> self-audit skip").
# Kept in sync with CLAIM_RE there; duplicated because scripts/ is not an
# installable package and the scanner must not depend on it at runtime.
_CLAIM_RE = re.compile(
    r"#\s*(?P<total>\d+)\s+tests\s+\((?P<passed>\d+)\s+passing,\s+"
    r"(?P<skipped>\d+)\s+self-audit skip"
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def scanner_version() -> str:
    """Git short SHA of the scanner checkout, or the package version."""
    try:
        out = subprocess.run(
            ["git", "-C", str(_REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        sha = out.stdout.strip()
        if out.returncode == 0 and sha:
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    from . import __version__
    return __version__


@lru_cache(maxsize=1)
def suite_counts() -> "dict[str, int] | None":
    """The scanner's canonical (CI-gated) suite counts, or None."""
    readme = _REPO_ROOT / "README.md"
    try:
        text = readme.read_text(encoding="utf-8")
    except OSError:
        return None
    m = _CLAIM_RE.search(text)
    if not m:
        return None
    return {
        "total": int(m.group("total")),
        "passed": int(m.group("passed")),
        "skipped": int(m.group("skipped")),
    }
