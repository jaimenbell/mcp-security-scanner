"""Wave-1 FP class 2: RegExp.prototype.exec() must not be conflated with
child_process.exec()/execSync() in the JS/TS shell-injection check.

Evidence (ecosystem-scan-2026-07-23): GLips/Figma-Context-MCP's
scripts/scan-hidden-chars.mjs (3 RegExp .exec() calls in the same file as a
real execSync call) and wonderwhy-er/DesktopCommanderMCP's
src/search-manager.ts (`wtRe.exec(xml)`, `wtRe` a `new RegExp(...)`
variable, also in a file importing child_process). Both anonymized into
tests/fixtures/vuln_param_regexp_exec_js/.

Fixed structurally: resolve the call's receiver (RegExp literal, `new
RegExp(...)`, or a same-file variable assigned one) rather than matching
any bare `.exec(`/`execSync(` in a file that merely imports child_process
ANYWHERE. An unresolvable receiver, a literal `child_process` receiver, or
a bare/aliased exec(...) call (no receiver -- the destructured-import shape)
must all still flag -- the over-flag-safe direction."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector


def _shell_hits(target):
    r = scan_repo(f"tests/fixtures/{target}", [ParamInjectionDetector()])
    return [f for f in r.findings if f.vuln_class == "shell-injection"]


def test_regexp_literal_exec_not_flagged():
    hits = _shell_hits("vuln_param_regexp_exec_js")
    # The exact FP lines from the real ecosystem shapes: 3 RegExp .exec()
    # calls in scan-hidden-chars.mjs, 1 in search-manager.ts. Real execSync
    # sinks in the same two files (checked separately below) must survive.
    fp_lines = {
        ("scan-hidden-chars.mjs", 13), ("scan-hidden-chars.mjs", 17),
        ("scan-hidden-chars.mjs", 21), ("search-manager.ts", 10),
    }
    hit_lines = {(f.file.split("/")[-1], f.line) for f in hits}
    overlap = fp_lines & hit_lines
    assert overlap == set(), f"RegExp.exec() calls must not flag as shell-injection, got {overlap}"


def test_real_execsync_in_same_file_still_flagged():
    hits = _shell_hits("vuln_param_regexp_exec_js")
    real = [f for f in hits if "execSync" in (f.title or "") or "child_process" in (f.detail or "")]
    files_hit = {f.file.split("/")[-1] for f in real}
    assert "scan-hidden-chars.mjs" in files_hit, (
        f"the real execSync sink in scan-hidden-chars.mjs must still flag, got {hits}"
    )
    assert "search-manager.ts" in files_hit, (
        f"the real execSync sink in search-manager.ts must still flag, got {hits}"
    )


def test_direct_child_process_receiver_still_flagged():
    hits = _shell_hits("vuln_param_regexp_exec_js")
    still = [f for f in hits if f.file.endswith("still_flagged.js")]
    lines = {f.line for f in still}
    # direct(): child_process.exec(cmd) at line 9
    assert 9 in lines, f"child_process.exec(cmd) direct call must flag, got {still}"


def test_destructured_alias_still_flagged():
    hits = _shell_hits("vuln_param_regexp_exec_js")
    still = [f for f in hits if f.file.endswith("still_flagged.js")]
    lines = {f.line for f in still}
    assert 13 in lines, f"run(cmd) -- destructured exec alias -- must flag, got {still}"


def test_bare_exec_call_still_flagged():
    hits = _shell_hits("vuln_param_regexp_exec_js")
    still = [f for f in hits if f.file.endswith("still_flagged.js")]
    lines = {f.line for f in still}
    assert 17 in lines, f"bare exec(cmd) call must flag, got {still}"


def test_unresolvable_receiver_still_flagged():
    hits = _shell_hits("vuln_param_regexp_exec_js")
    still = [f for f in hits if f.file.endswith("still_flagged.js")]
    lines = {f.line for f in still}
    assert 23 in lines, f"thing.exec(str) -- unresolvable receiver -- must stay flagged, got {still}"
