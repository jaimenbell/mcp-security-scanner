"""Slice 2 of the receiver-binding fix: receiver CLASSIFICATION in
`_is_mutating_sink_call`.

The attribute branch matched any name in `_MUTATING_SINK_SHORT` **regardless of
what the call was made ON** -- explicitly, in a comment that called it
"structural": `ANY real attribute access matches the short-name fallback
regardless of what the receiver is`. That was the right fix for its own bug
(round 2's refuter B: `Path(x).unlink()` was being missed because `_dotted`
collapses a non-`Name` receiver to a bare leaf), and it is a false-positive
generator in its own right, because it reads `remove`/`delete`/`put`/`post`/
`run`/`patch` as sinks on receivers that are nothing of the kind.

Measured over the 13-repo ecosystem-scan corpus (3,831 parsed Python files),
the attribute branch fires 2,199 times. The top receivers are `mocker.patch`
(375), `mock.patch` (228), `asyncio.run` (199), `mcp.run` (110),
`self.wrapper.call` (71), `logger.remove` (34) -- and 12 of them are
`db_connection_map.remove(...)`, an in-memory connection registry, which is
the shape that reaches an actual published finding: three AWS Labs database
MCP servers' `connect_to_database` tools flagged P1 on a dict drop.

THE FIX BINDS THE RECEIVER, and only demotes on proof:

  * receiver is a module-level name bound to a constructor call for a class
    this scan can point at (same file, or via `_build_import_map`), AND
  * that class defines the method being called

-> the call is a repo-internal method call, not a sink by itself. This is not
a new law: it is the existing bare-`Name` law (`ctx.local_names` -> "resolvable
to a repo-internal function -- NOT a sink by itself; the one-hop resolver
inspects that function's REAL body elsewhere") extended from `foo()` to
`x.foo()`.

UNKNOWN-RECEIVER DEFAULT: **flag when unknown.** Anything not proven above
keeps its pre-existing flag. This is why slice 1 had to land first -- the
demotion's proof condition is *exactly* the condition under which slice 1's
step 2b follows the call, so nothing is given up: the sink is still found one
hop in, where it really lives (`test_receiver_binding_still_flags_the_methods_own_real_sink`).
"""
from __future__ import annotations

import ast
from pathlib import Path

from mcp_scanner.detectors import ToolScopeCreepDetector
from mcp_scanner.detectors.base import SourceFile
from mcp_scanner.detectors.tool_scope_creep import (
    _SinkFileCtx,
    _build_sink_file_ctx,
    _is_mutating_sink_call,
)
from mcp_scanner.models import Confidence, Severity
from mcp_scanner.scanner import scan_repo


def _hits(result):
    return [f for f in result.findings if f.vuln_class == "tool-scope-creep"]


def _call_from_src(src: str) -> ast.Call:
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            return node
    raise AssertionError(f"no call found in: {src}")


def _source_file(src: str, rel: str = "server.py") -> SourceFile:
    return SourceFile(
        path=Path(rel),
        rel=rel,
        text=src,
        tree=ast.parse(src),
        lines=src.splitlines(),
    )


# --------------------------------------------------------------------- #
# End-to-end: the false positive, and the true positive it must not take
# down with it.
# --------------------------------------------------------------------- #
def test_internal_instance_method_is_not_a_sink_by_its_short_name(fixtures_dir):
    """THE FALSE POSITIVE. `db_connection_map` is a `ConnectionRegistry`
    instance and `.remove()` is that class's own dict drop. The tool's name is
    non-mutating and no sink exists anywhere in the fixture, so a finding here
    can only be the receiver-agnostic short-name match."""
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_receiver_binding_internal_method"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        "a method call on a proven repo-internal instance must be classified "
        "by its receiver, not by its short name -- got: "
        f"{[(f.vuln_class, f.file, f.line, f.title) for f in result.findings]}"
    )


def test_receiver_binding_still_flags_the_methods_own_real_sink(fixtures_dir):
    """RECALL GUARD, and the load-bearing half of this slice. Identical shape,
    but the resolved method's own body holds an ungated `os.remove`. Slice 1's
    hop resolves the instance receiver to exactly that method, so demoting the
    call site costs no reach -- the sink is found one hop in. A precision fix
    that failed here would be silence dressed as precision."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_receiver_binding_real_sink"),
        [ToolScopeCreepDetector()],
    )
    hits = _hits(result)
    titles = " ".join(f.title for f in hits)
    assert "lookup_status" in titles, (
        "expected lookup_status flagged via its instance method's own "
        f"os.remove, got: {result.findings}"
    )
    assert any(f.severity == Severity.P1 for f in hits)
    assert any(f.confidence == Confidence.HIGH for f in hits)


def test_unknown_receiver_still_flags(fixtures_dir):
    """THE DEFAULT, pinned. `client` is provably an instance -- of a
    third-party `httpx.Client` this scan cannot open. That is not proof of a
    repo-internal method, and a third-party handle is exactly where a real
    network sink lives, so `client.post(...)` keeps its flag."""
    result = scan_repo(
        str(fixtures_dir / "vuln_tool_scope_receiver_binding_unknown_receiver"),
        [ToolScopeCreepDetector()],
    )
    titles = " ".join(f.title for f in _hits(result))
    assert "lookup_status" in titles, (
        "an unresolvable receiver must keep its flag (over-flag-safe), got: "
        f"{result.findings}"
    )


def test_receiver_binding_resolves_across_an_explicit_import(fixtures_dir):
    """CROSS-FILE. The class is bound by an explicit same-repo import, so the
    proof has to run through `_build_import_map` -- the same machinery the hop
    uses to follow this call, which is what makes the demotion safe."""
    result = scan_repo(
        str(fixtures_dir / "clean_tool_scope_receiver_binding_cross_file"),
        [ToolScopeCreepDetector()],
    )
    assert result.findings == [], (
        "an instance of a class bound by an explicit same-repo import must "
        "resolve the same way a same-file one does -- got: "
        f"{[(f.vuln_class, f.file, f.line, f.title) for f in result.findings]}"
    )


# --------------------------------------------------------------------- #
# Unit: the classification itself, and every way the proof is allowed to
# FAIL (each failure keeping the pre-existing flag).
# --------------------------------------------------------------------- #
def test_proven_internal_receiver_demotes_only_that_pair():
    call = _call_from_src("db_connection_map.remove(key)")
    proven = _SinkFileCtx(internal_receiver_methods=frozenset({("db_connection_map", "remove")}))
    assert _is_mutating_sink_call(call, proven) is False

    other_method = _call_from_src("db_connection_map.delete(key)")
    assert _is_mutating_sink_call(other_method, proven) is True, (
        "the proof is per (receiver, method) pair -- proving one method on a "
        "receiver must not vouch for a different one"
    )
    other_receiver = _call_from_src("cache.remove(key)")
    assert _is_mutating_sink_call(other_receiver, proven) is True


def test_no_ctx_degrades_to_the_pre_existing_flag():
    call = _call_from_src("db_connection_map.remove(key)")
    assert _is_mutating_sink_call(call, None) is True, (
        "with no resolution context available at all the attribute branch "
        "must behave exactly as it did before this slice"
    )
    assert _is_mutating_sink_call(call, _SinkFileCtx()) is True


def test_real_sinks_are_untouched_by_receiver_classification():
    """The three shapes previous rounds fought hardest to keep: an exact
    dotted stdlib sink, a non-`Name` receiver (refuter B's `Path(x).unlink()`),
    and a plain third-party attribute sink."""
    proven = _SinkFileCtx(internal_receiver_methods=frozenset({("os", "remove"), ("requests", "post")}))
    assert _is_mutating_sink_call(_call_from_src("os.remove(p)"), proven) is True, (
        "an exact-match dotted stdlib sink is decided before receiver "
        "classification and must never be demotable by it"
    )
    assert _is_mutating_sink_call(_call_from_src("Path(x).unlink()"), None) is True
    assert _is_mutating_sink_call(_call_from_src("requests.Session().post(url)"), None) is True
    assert _is_mutating_sink_call(_call_from_src("session.post(url)"), None) is True


# --------------------------------------------------------------------- #
# Unit: how the proof is BUILT -- the four ways it must refuse to fire.
# --------------------------------------------------------------------- #
def test_builder_proves_a_module_level_instance_of_a_same_file_class():
    f = _source_file(
        "class Registry:\n"
        "    def remove(self, k):\n"
        "        self._d.pop(k, None)\n"
        "\n"
        "reg = Registry()\n"
    )
    ctx = _build_sink_file_ctx(f, {f.rel: f})
    assert ("reg", "remove") in ctx.internal_receiver_methods


def test_builder_refuses_a_method_the_class_does_not_define():
    """No inherited/dynamic-attribute guessing: if the class does not define
    the method, nothing is proven and the flag stands."""
    f = _source_file(
        "class Registry:\n"
        "    def purge(self, k):\n"
        "        self._d.pop(k, None)\n"
        "\n"
        "reg = Registry()\n"
    )
    ctx = _build_sink_file_ctx(f, {f.rel: f})
    assert ("reg", "remove") not in ctx.internal_receiver_methods
    assert _is_mutating_sink_call(_call_from_src("reg.remove(k)"), ctx) is True


def test_builder_refuses_a_receiver_rebound_outside_module_level():
    """The proof reads module level only. A name also assigned inside some
    function body may be a different object entirely at the call site, so the
    module-level binding proves nothing about it."""
    f = _source_file(
        "class Registry:\n"
        "    def remove(self, k):\n"
        "        self._d.pop(k, None)\n"
        "\n"
        "reg = Registry()\n"
        "\n"
        "def swap():\n"
        "    global reg\n"
        "    reg = open_real_thing()\n"
    )
    ctx = _build_sink_file_ctx(f, {f.rel: f})
    assert ("reg", "remove") not in ctx.internal_receiver_methods


def test_builder_ignores_a_global_declaration_that_never_assigns():
    """The counterpart to the test above, and a measured decision rather than
    a stylistic one. A bare `global x` cannot rebind anything -- the
    assignment that would is a Store, already counted. Treating the
    declaration itself as a binding split three byte-identical real servers
    on a no-op statement: mssql and postgres declare `global db_connection_map`
    in functions that never assign it, oracle does not declare it at all, and
    all three bind the name exactly once, at module level."""
    f = _source_file(
        "class Registry:\n"
        "    def remove(self, k):\n"
        "        self._d.pop(k, None)\n"
        "\n"
        "reg = Registry()\n"
        "\n"
        "def touch(k):\n"
        "    global reg\n"
        "    return reg.remove(k)\n"
    )
    ctx = _build_sink_file_ctx(f, {f.rel: f})
    assert ("reg", "remove") in ctx.internal_receiver_methods
    assert _is_mutating_sink_call(_call_from_src("reg.remove(k)"), ctx) is False


def test_builder_refuses_an_unresolvable_or_non_constructor_binding():
    """Two refusals in one: a third-party constructor (class not in this
    scan) and a binding that is not a call at all."""
    f = _source_file(
        "import httpx\n"
        "\n"
        "client = httpx.Client()\n"
        "alias = SomeClass\n"
    )
    ctx = _build_sink_file_ctx(f, {f.rel: f})
    assert not any(r == "client" for r, _ in ctx.internal_receiver_methods)
    assert not any(r == "alias" for r, _ in ctx.internal_receiver_methods)
    assert _is_mutating_sink_call(_call_from_src("client.post(url)"), ctx) is True
