"""Ecosystem-scan v2 pipeline + its hard disclosure rails (spec 2026-07-23,
wave-10 Lane A).

The pipeline turns the hand-done ecosystem scan into a repeatable tool. These
tests pin BOTH the mechanics (config -> clone/scan -> per-repo report +
aggregate roll-up) AND the non-negotiable disclosure rails:

  R1  No third-party org/repo name lands in any TRACKED file, ever -- the
      aggregate + raw results + disclosure notes are gitignored local
      artifacts only. Proven with a SENTINEL target name that cannot
      pre-exist in the repo.
  R2  Any finding above LOW confidence is a DISCLOSURE CANDIDATE, surfaced
      PRIVATE / operator-review-required, following the target's OWN
      SECURITY policy (read from the clone, never invented).
  R3  Read-only toward third-party repos -- clone + scan, never write back.
  R4  No network in tests: the clone function is injected; the real clone
      path is exercised only via a local-path fixture (local paths never
      clone).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_scanner import ecosystem_scan as eco

FIXTURES = Path(__file__).parent / "fixtures"
VULN = str(FIXTURES / "vuln_codegen")   # 2x P1/medium codegen-injection
CLEAN = str(FIXTURES / "clean_auth")    # clean bill

# A name that provably does not appear anywhere in the tracked tree, so any
# leak into a tracked file is unambiguous.
SENTINEL_A = "SENTINEL_ORG_zeta_do_not_track_alpha"
SENTINEL_B = "SENTINEL_ORG_zeta_do_not_track_beta"


# ------------------------------------------------------------------ #
# config / targets
# ------------------------------------------------------------------ #
def _write_config(tmp_path: Path, targets: list[dict]) -> Path:
    p = tmp_path / "targets.json"
    p.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    return p


def test_load_targets_detects_url_vs_local_path(tmp_path):
    cfg = _write_config(tmp_path, [
        {"name": "local-one", "location": "/some/local/path"},
        {"name": "remote-one", "location": "https://example.test/org/repo.git"},
        {"name": "ssh-one", "location": "git@example.test:org/repo.git"},
    ])
    targets = eco.load_targets(cfg)
    by_name = {t.name: t for t in targets}
    assert by_name["local-one"].is_url is False
    assert by_name["remote-one"].is_url is True
    assert by_name["ssh-one"].is_url is True


def test_load_targets_bad_config_is_clean_error(tmp_path):
    bad = tmp_path / "nope.json"
    with pytest.raises(eco.EcosystemScanError):
        eco.load_targets(bad)


# ------------------------------------------------------------------ #
# R4 -- no network; local path never clones, URL routes through injected clone
# ------------------------------------------------------------------ #
def test_local_path_target_never_clones(tmp_path):
    """A local-path target is scanned in place -- the clone function is
    never called (so a local run makes zero network calls)."""
    calls = []

    def _boom_clone(url, dest, **kw):  # pragma: no cover - must never run
        calls.append(url)
        raise AssertionError("clone must not be called for a local path")

    t = eco.Target(name="x", location=VULN, is_url=False)
    resolved = eco.resolve_target(t, tmp_path / "scratch", clone=_boom_clone)
    assert Path(resolved) == Path(VULN)
    assert calls == []


def test_url_target_routes_through_injected_clone_no_network(tmp_path):
    """A URL target is cloned via the injected function; the real git
    subprocess clone is never touched in tests."""
    seen = {}

    def _fake_clone(url, dest, **kw):
        seen["url"] = url
        dest = Path(dest)
        shutil.copytree(VULN, dest, dirs_exist_ok=True)
        return dest

    t = eco.Target(name="remote", location="https://example.test/o/r.git",
                   is_url=True)
    resolved = eco.resolve_target(t, tmp_path / "scratch", clone=_fake_clone)
    assert seen["url"] == "https://example.test/o/r.git"
    assert (Path(resolved) / "generator.py").exists()


def test_real_clone_helper_uses_shallow_git_and_is_injectable():
    """The default clone helper issues a shallow `git clone --depth 1` and
    accepts an injected runner (so tests never spawn git / hit the network)."""
    recorded = {}

    def _fake_run(cmd, **kw):
        recorded["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    eco.shallow_clone("https://example.test/o/r.git", "/tmp/dest", run=_fake_run)
    cmd = recorded["cmd"]
    assert cmd[:2] == ["git", "clone"]
    assert "--depth" in cmd and "1" in cmd
    assert "https://example.test/o/r.git" in cmd


# ------------------------------------------------------------------ #
# R3 -- read-only toward the target repo
# ------------------------------------------------------------------ #
def test_scan_is_read_only_toward_target(tmp_path):
    """Scanning a local target mutates nothing in it (mtime + content of
    every file unchanged)."""
    work = tmp_path / "target"
    shutil.copytree(VULN, work)
    before = {p: (p.stat().st_mtime_ns, p.read_bytes())
              for p in work.rglob("*") if p.is_file()}

    t = eco.Target(name="ro", location=str(work), is_url=False)
    eco.scan_targets([t], tmp_path / "scratch")

    after = {p: (p.stat().st_mtime_ns, p.read_bytes())
             for p in work.rglob("*") if p.is_file()}
    assert before == after


# ------------------------------------------------------------------ #
# aggregate roll-up
# ------------------------------------------------------------------ #
def _two_target_results() -> dict:
    from mcp_scanner.scanner import scan_repo
    return {
        SENTINEL_A: scan_repo(VULN).to_dict(),
        SENTINEL_B: scan_repo(CLEAN).to_dict(),
    }


def test_build_aggregate_counts_across_targets():
    agg = eco.build_aggregate(_two_target_results())
    assert agg["repos_scanned"] == 2
    assert agg["clean_bill_count"] == 1              # CLEAN
    assert agg["repos_with_findings"] == 1           # VULN
    assert agg["by_severity"]["P1"] == 2
    assert agg["by_confidence"]["medium"] == 2
    assert agg["by_class"].get("codegen-injection") == 2
    assert agg["raw_p0_p1"] == 2
    # medium confidence is above LOW -> disclosure candidates
    assert agg["disclosure_candidate_count"] == 2
    assert agg["repos_with_disclosure_candidates"] == 1


def test_aggregate_markdown_is_anonymized_no_target_names():
    agg = eco.build_aggregate(_two_target_results())
    md = eco.render_aggregate_markdown(agg)
    assert SENTINEL_A not in md
    assert SENTINEL_B not in md
    # still carries the raw-vs-triaged framing + a real count
    assert "codegen-injection" in md
    assert "2" in md


# ------------------------------------------------------------------ #
# R2 -- disclosure candidates PRIVATE + real SECURITY channel, never invented
# ------------------------------------------------------------------ #
def test_disclosure_candidates_are_above_low_confidence():
    from mcp_scanner.scanner import scan_repo
    scan = scan_repo(VULN).to_dict()
    cands = eco.disclosure_candidates(scan)
    assert cands and all(c["confidence"] in ("medium", "high") for c in cands)


def test_read_security_policy_reads_not_invents(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github").mkdir(parents=True)
    (repo / ".github" / "SECURITY.md").write_text(
        "Email security@theproject.test to report.", encoding="utf-8")
    pol = eco.read_security_policy(repo)
    assert pol is not None
    assert "security@theproject.test" in pol


def test_read_security_policy_absent_returns_none(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    assert eco.read_security_policy(repo) is None


def test_disclosure_note_is_marked_private_and_surfaces_channel(tmp_path):
    from mcp_scanner.scanner import scan_repo
    scan = scan_repo(VULN).to_dict()
    note = eco.render_disclosure_note(
        SENTINEL_A, scan, security_policy="Email security@theproject.test")
    assert "PRIVATE" in note
    assert "operator review required" in note.lower()
    assert "not sent" in note.lower()
    assert "security@theproject.test" in note        # real channel surfaced


def test_disclosure_note_when_no_security_policy_says_operator_must_locate(tmp_path):
    from mcp_scanner.scanner import scan_repo
    scan = scan_repo(VULN).to_dict()
    note = eco.render_disclosure_note(SENTINEL_A, scan, security_policy=None)
    low = note.lower()
    # never fabricates a channel; explicitly tells the operator to find it
    assert "no security policy" in low or "no security.md" in low
    assert "operator" in low


# ------------------------------------------------------------------ #
# R1 -- artifacts gitignored; nothing leaks into the tracked tree
# ------------------------------------------------------------------ #
def _git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(eco.repo_root()), *args],
                          capture_output=True, text=True)


def test_default_artifact_dirs_are_gitignored():
    """The default artifacts / scratch / real-config paths must be ignored,
    so their (name-bearing) contents can never be committed."""
    # dir patterns are trailing-slash; probe a child path (what actually
    # gets written). the config is a file pattern -- probe it directly.
    for probe in (eco.DEFAULT_OUT_DIRNAME + "/raw-results.json",
                  eco.DEFAULT_SCRATCH_DIRNAME + "/some-repo",
                  eco.DEFAULT_CONFIG_NAME):
        r = _git("check-ignore", probe)
        assert r.returncode == 0, f"{probe} is NOT gitignored (rc={r.returncode})"


def test_full_run_leaks_no_target_name_into_tracked_files(tmp_path):
    """End-to-end rail: run against SENTINEL-named targets writing to the
    REAL default in-repo artifacts dir, then prove (a) every artifact is
    gitignored, (b) the tree stays clean, (c) no tracked file contains the
    sentinel name."""
    root = eco.repo_root()
    out_dir = root / eco.DEFAULT_OUT_DIRNAME
    scratch = root / eco.DEFAULT_SCRATCH_DIRNAME
    # sanity: start clean
    if out_dir.exists():
        shutil.rmtree(out_dir)
    if scratch.exists():
        shutil.rmtree(scratch)

    # Runtime-unique target names so the sentinel provably cannot pre-exist
    # in ANY source file (incl. this test file) -- any appearance in a
    # tracked file is then unambiguously a leak the scan caused.
    import uuid
    run_a = "ecoLEAKPROBE" + uuid.uuid4().hex
    run_b = "ecoLEAKPROBE" + uuid.uuid4().hex
    cfg = _write_config(tmp_path, [
        {"name": run_a, "location": VULN},
        {"name": run_b, "location": CLEAN},
    ])
    try:
        summary = eco.run_ecosystem_scan(cfg, out_dir=out_dir, scratch_dir=scratch)
        # produced the artifacts
        produced = list(out_dir.rglob("*"))
        assert any(p.name == "aggregate-report.md" for p in produced)
        assert any(p.name == "raw-results.json" for p in produced)
        assert summary["disclosure_notes"] >= 1

        # (a) every produced file is git-ignored
        for p in produced:
            if p.is_file():
                rc = _git("check-ignore", str(p)).returncode
                assert rc == 0, f"produced artifact not ignored: {p}"

        # (b) working tree carries no new tracked/untracked-unignored entry
        status = _git("status", "--porcelain").stdout
        assert eco.DEFAULT_OUT_DIRNAME not in status
        assert eco.DEFAULT_SCRATCH_DIRNAME not in status

        # (c) the sentinel name is in NO tracked file
        tracked = _git("ls-files").stdout.split("\n")
        for rel in tracked:
            rel = rel.strip()
            if not rel:
                continue
            fp = root / rel
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            assert run_a not in text, f"sentinel leaked into tracked {rel}"
            assert run_b not in text, f"sentinel leaked into tracked {rel}"

        # the aggregate itself is anonymized even though it lives private
        agg_md = (out_dir / "aggregate-report.md").read_text(encoding="utf-8")
        assert run_a not in agg_md and run_b not in agg_md
    finally:
        if out_dir.exists():
            shutil.rmtree(out_dir)
        if scratch.exists():
            shutil.rmtree(scratch)


def test_run_emits_per_repo_reports_and_raw_results(tmp_path):
    """Per-repo report_generator render + a raw-results mapping land in the
    (caller-chosen, gitignored-by-default) out dir."""
    out_dir = tmp_path / "art"
    scratch = tmp_path / "scr"
    cfg = _write_config(tmp_path, [
        {"name": SENTINEL_A, "location": VULN},
        {"name": SENTINEL_B, "location": CLEAN},
    ])
    summary = eco.run_ecosystem_scan(cfg, out_dir=out_dir, scratch_dir=scratch)
    raw = json.loads((out_dir / "raw-results.json").read_text(encoding="utf-8"))
    assert set(raw.keys()) == {SENTINEL_A, SENTINEL_B}
    # a per-repo report exists for each target
    assert summary["per_repo_reports"] == 2
    reports = list(out_dir.glob("report-*.md"))
    assert len(reports) == 2
