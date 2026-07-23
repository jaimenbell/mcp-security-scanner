"""Round-2 N-vote P0-2 fix: RegExp-variable resolution for the
.exec()/child_process conflation fix (class 2, wave 1) must be SCOPED, not
a flat file-wide name set. Both refuters proved live: a RegExp variable
declared in one function masks a real child_process.exec() sink of the
SAME NAME in a completely different, unrelated function (no lexical
relationship) -- confirmed in both directions (`cp` and `cursor`).

Fixed via brace-scoped resolution: a RegExp-var declaration is only
visible at a usage site if that site falls within the declaration's own
innermost enclosing block (or the declaration is at module/top level,
which real JS closures make visible everywhere)."""
from mcp_scanner.scanner import scan_repo
from mcp_scanner.detectors import ParamInjectionDetector


def _shell_hits():
    r = scan_repo("tests/fixtures/vuln_param_regexp_scope_fp", [ParamInjectionDetector()])
    return [f for f in r.findings if f.vuln_class == "shell-injection"]


def test_local_shadow_regex_still_demoted_within_its_own_function():
    hits = _shell_hits()
    lines = {f.line for f in hits}
    # safeSearch's `cp.exec(text)` at line 11 -- local RegExp shadow, safe.
    assert 11 not in lines, f"local RegExp shadow must demote within its own function, got {hits}"


def test_outer_child_process_binding_not_masked_by_unrelated_local_shadow():
    hits = _shell_hits()
    lines = {f.line for f in hits}
    # runCommand's `cp.exec(userInput)` at line 18 -- resolves to the OUTER
    # module-level `const cp = require("child_process")`, NOT safeSearch's
    # local regex shadow. Must stay flagged.
    assert 18 in lines, f"outer child_process binding must not be masked by an unrelated local RegExp shadow, got {hits}"


def test_cursor_local_regex_still_demoted_within_its_own_function():
    hits = _shell_hits()
    lines = {f.line for f in hits}
    assert 23 not in lines, f"parsePage's local cursor regex must demote, got {hits}"


def test_cursor_child_process_in_different_function_not_masked():
    hits = _shell_hits()
    lines = {f.line for f in hits}
    # fetchNext's `cursor.exec(userInput)` -- a DIFFERENT function's local
    # child_process binding, unrelated to parsePage's same-named regex.
    assert 32 in lines, f"fetchNext's own child_process cursor binding must not be masked, got {hits}"


def test_module_level_regex_still_demotes_inside_nested_function():
    # Control: ancestor/closure-visible module-level regex vars must still
    # resolve correctly -- scoping must not regress the original fix.
    hits = _shell_hits()
    lines = {f.line for f in hits}
    assert 42 not in lines, f"module-level regex used in a nested function must still demote, got {hits}"
