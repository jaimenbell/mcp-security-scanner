"""Slice 1 of the receiver-binding fix: instance-receiver one-hop resolution.

`_resolve_call_targets` step 2 disambiguates a class-qualified call, but its
bare-`Name` receiver branch only ever read that name as a CLASS
(`ClassName.method(...)`). The overwhelmingly more common real shape --
a module-level or local INSTANCE, `db_connection_map.purge_entry(...)` --
therefore never resolved, and fell through to step 3's same-file bare-name
guess: every function in the file sharing the method's short name became a
candidate, sink status OR'd across all of them.

That fallback is the same generous-name-edge hazard `bea0e90` closed in
`reachability.py` (a callee followed by short name repo-wide, which graded an
unshipped test double REACHABLE off a namesake). Here it grades an unrelated
module-level helper's `os.remove` as the tool's sink.

The fix binds the receiver: same-scope `name = ClassName(...)` -> that exact
class's own method, resolved in this file or, via `_build_import_map`, in the
file the class was imported from. When the receiver is provably an instance
but the class cannot be resolved, the call is an honest miss (`None`) -- it
must NEVER re-enter the bare-name guess, which is the whole point of the
slice.

Out of scope here, deliberately: receiver CLASSIFICATION in
`_is_mutating_sink_call` (the receiver-agnostic attribute branch) and
HTTP-verb severity calibration. Every method name used below is chosen to sit
OUTSIDE `_MUTATING_SINK_SHORT` so these tests isolate the hop and do not
quietly depend on either of those later slices.
"""
from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.models import Confidence, Severity
from mcp_scanner.scanner import scan_repo


def _hits(result):
    return [f for f in result.findings if f.vuln_class == "tool-scope-creep"]


def test_instance_receiver_does_not_inherit_a_namesake_helpers_sink(fixtures_dir):
    """THE FALSE POSITIVE. `db_connection_map` is a `ConnectionRegistry`
    instance whose `purge_entry` only pops a dict entry. An unrelated
    module-level `purge_entry` in the same file does `os.remove`. The tool's
    name is non-mutating, so a finding here can only have come from the
    bare-name guess crediting the namesake's sink to the instance call."""
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_instance_receiver_hop"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        "an instance receiver must resolve to its own class's method, never "
        "to an unrelated same-named module-level helper's sink -- got: "
        f"{[(f.vuln_class, f.file, f.line, f.title) for f in result.findings]}"
    )


def test_instance_receiver_still_flags_its_own_methods_real_sink(fixtures_dir):
    """RECALL GUARD. Same shape, but the resolved instance method is the one
    holding the real ungated `os.remove`. Precision bought by going blind is
    not precision -- this must still flag."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_instance_receiver_sink"),
        [ToolScopeCreepDetector()],
    )
    hits = _hits(result)
    titles = " ".join(f.title for f in hits)
    assert "sync_state" in titles, (
        f"expected sync_state flagged via its instance method's own sink, "
        f"got: {result.findings}"
    )
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_instance_receiver_resolves_across_an_explicit_import(fixtures_dir):
    """CROSS-FILE. The class is bound by an explicit same-repo import and
    then instantiated. Nothing resolved this before: step 1 keys on the call's
    head (`db`, absent from the import map), step 2 read `db` as a class name,
    step 3 found no same-file `purge_entry`. The genuinely ungated cross-file
    sink went unflagged."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_instance_receiver_cross_file"),
        [ToolScopeCreepDetector()],
    )
    hits = _hits(result)
    titles = " ".join(f.title for f in hits)
    assert "sync_state" in titles, (
        f"expected sync_state flagged via the imported class's own method, "
        f"got: {result.findings}"
    )


def test_unresolvable_instance_receiver_never_falls_back_to_the_name_guess(fixtures_dir):
    """THE HAZARD, pinned. `client` is an instance of a third-party class not
    in this repo. The receiver is provably an instance, so it is provably NOT
    a same-file class or module -- and the same-file bare-name fallback is
    therefore provably wrong for it, namesake `purge_entry` sink and all.
    An unresolvable hop is a disclosed miss, never a guess."""
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_instance_receiver_external_class"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        "a provably-instance receiver whose class is outside this repo must "
        "be an honest miss, not a same-file bare-name guess -- got: "
        f"{[(f.vuln_class, f.file, f.line, f.title) for f in result.findings]}"
    )
