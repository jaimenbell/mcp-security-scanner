"""`rm -rf node_modules` is a build step, not a destructive-ops hazard.

FROM THE 2026-07-29 HELD-OUT MEASUREMENT, the build-script half of class (iv).
airtable-mcp-server `build-mcpb.sh` produced 2 P1 `job-destructive-no-confirm`
findings:

    :17   rm -rf node_modules                  (before `npm ci --omit=dev`)
    :23   rm -rf airtable-mcp-server.mcpb      (its own build output)

both under `set -euo pipefail`. Deleting a regenerable build artifact is the
normal, correct shape of a build script; demanding a confirm-before-destroy
gate in front of it is noise, and at P1 it outranked real findings.

THE RULE, WITH ITS SCOPE ATTACHED: demotion applies only when EVERY target on
the line is a curated build-artifact name (`node_modules`, `dist`, `build`,
`coverage`, `__pycache__`, `.venv`, ...) or a build-output archive suffix
(`.mcpb`, `.zip`, `.tgz`, `.whl`). One unrecognised target -- a variable, a
path, an absolute directory -- and the whole line keeps its original severity.
Curated exact-match names only: no globs, no prefix matching, no "looks like a
build dir".

It DEMOTES to P3/LOW and tags; it never drops. A build script that wipes
`node_modules` is still visible in the report, just not ranked as an
irreversible-destruction hazard.
"""
from pathlib import Path

import pytest

from mcp_scanner.detectors import JobHazardsDetector
from mcp_scanner.detectors.base import RepoContext, SourceFile
from mcp_scanner.models import Confidence, Severity


def _destructive(text: str, rel: str = "build.sh"):
    sf = SourceFile(path=Path(rel), rel=rel, text=text, tree=None,
                    lines=text.splitlines())
    ctx = RepoContext(root=Path("."), files=[sf], tracked=set(), is_git=False)
    return [f for f in JobHazardsDetector().run(ctx)
            if f.vuln_class == "job-destructive-no-confirm"]


# --- the measured false positives ------------------------------------------
def test_the_measured_airtable_build_script_demotes_both_lines():
    src = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "rm -rf node_modules\n"
        "npm ci --omit=dev --audit false --fund false\n"
        "rm -rf airtable-mcp-server.mcpb\n"
    )
    hits = _destructive(src, rel="build-mcpb.sh")
    assert len(hits) == 2, "never dropped -- both lines must still be reported"
    for f in hits:
        assert f.severity is Severity.P3
        assert f.confidence is Confidence.LOW
        assert "build-artifact" in f.title


@pytest.mark.parametrize("line", [
    "rm -rf node_modules",
    "rm -rf dist",
    "rm -rf build coverage",
    "rm -rf __pycache__",
    "rm -rf .venv",
    "rm -rf out/ .next",
    "rm -rf mypkg.egg-info",
    "rm -rf release.zip",
    "rm -rf bundle.tgz",
    "rm -fr dist",
])
def test_curated_build_artifact_targets_demote(line):
    hits = _destructive(f"#!/bin/sh\n{line}\n")
    assert len(hits) == 1
    assert hits[0].severity is Severity.P3
    assert "build-artifact" in hits[0].title


# --- the recall half: everything else keeps its severity -------------------
@pytest.mark.parametrize("line", [
    "rm -rf ${testDir}",                 # a variable -- airtable's e2e harness
    "rm -rf $DEPLOY_DIR",
    "rm -rf /var/lib/postgres",
    "rm -rf ~/backups",
    "rm -rf data",
    "rm -rf .git",
    "rm -rf node_modules /etc/nginx",    # MIXED: one bad target poisons the line
    "rm -rf \"$HOME/.config\"",
])
def test_non_artifact_targets_keep_full_severity(line):
    hits = _destructive(f"#!/bin/sh\n{line}\n")
    assert len(hits) == 1, f"{line!r} must still be reported"
    assert hits[0].severity is Severity.P1, (
        f"{line!r} is not a curated build artifact and must not be demoted "
        f"(got {hits[0].severity})"
    )
    assert "build-artifact" not in hits[0].title


def test_a_bare_rm_rf_with_no_target_is_not_demoted():
    """Degenerate input must fail closed, not open."""
    hits = _destructive("#!/bin/sh\nrm -rf\n")
    if hits:
        assert hits[0].severity is Severity.P1


def test_demotion_does_not_apply_to_other_destructive_patterns():
    """SCOPE PIN. The carve-out is about regenerable build artifacts, so it
    must not leak onto a different destructive verb that merely mentions one."""
    hits = _destructive("#!/bin/sh\ngit push --force\nterraform destroy\n")
    assert hits
    assert all(f.severity is not Severity.P3 for f in hits)
    assert all("build-artifact" not in f.title for f in hits)
