"""Unit tests for ``tool_registry.dispatch_segments`` (2026-07-23) -- the
shared low-level SDK ``call_tool`` dispatch-branch walk consumed by both
``detectors/tool_scope_creep.py`` and ``detectors/secret_leak_response.py``.
"""
import ast

from mcp_scanner.tool_registry import dispatch_segments, _string_eq_literal


def _handler(src: str) -> ast.AST:
    tree = ast.parse(src)
    return tree.body[-1]


def test_string_eq_literal_matches_both_operand_orders():
    right = ast.parse('name == "search"', mode="eval").body
    left = ast.parse('"search" == name', mode="eval").body
    assert _string_eq_literal(right) == "search"
    assert _string_eq_literal(left) == "search"


def test_string_eq_literal_none_for_in_membership():
    test = ast.parse('name in ("a", "b")', mode="eval").body
    assert _string_eq_literal(test) is None


def test_string_eq_literal_none_for_non_eq_compare():
    test = ast.parse('name != "x"', mode="eval").body
    assert _string_eq_literal(test) is None


def test_multi_branch_dispatch_attributes_each_tool_name():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    if name == 'a':\n"
        "        return 1\n"
        "    elif name == 'b':\n"
        "        return 2\n"
        "    else:\n"
        "        return 3\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _ in segs]
    assert names == ["a", "b", None]


def test_ambiguous_membership_branch_is_none():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    if name == 'a':\n"
        "        return 1\n"
        "    elif name in ('b', 'c'):\n"
        "        return 2\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _ in segs]
    assert names == ["a", None]


def test_leftover_statements_outside_dispatch_are_none():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    audit(name)\n"
        "    if name == 'a':\n"
        "        return 1\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _ in segs]
    assert names == ["a", None]
    leftover_stmts = segs[-1][1]
    assert any(isinstance(s, ast.Expr) for s in leftover_stmts)


def test_no_dispatch_shape_falls_back_to_whole_body():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    return _DISPATCH[name](args)\n"
    )
    segs = dispatch_segments(handler)
    assert len(segs) == 1
    name, stmts = segs[0]
    assert name is None
    assert stmts == handler.body
