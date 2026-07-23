"""Unit tests for ``tool_registry.dispatch_segments`` (2026-07-23) -- the
shared low-level SDK ``call_tool`` dispatch-branch walk consumed by both
``detectors/tool_scope_creep.py`` and ``detectors/secret_leak_response.py``.

2026-07-23 (same day, N-vote fix pass): the return shape grew a third
``shared`` element (distinguishing a genuinely-shared pre-dispatch prefix
from an ambiguous/final-else branch -- P0-1), and the chain walk now
enforces a single, consistent discriminant across every link (P1).
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
    names = [n for n, _, _ in segs]
    assert names == ["a", "b", None]
    assert all(shared is False for _, _, shared in segs)


def test_ambiguous_membership_branch_is_none():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    if name == 'a':\n"
        "        return 1\n"
        "    elif name in ('b', 'c'):\n"
        "        return 2\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _, _ in segs]
    assert names == ["a", None]


def test_leftover_statements_before_dispatch_are_marked_shared():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    audit(name)\n"
        "    if name == 'a':\n"
        "        return 1\n"
    )
    segs = dispatch_segments(handler)
    names_and_shared = [(n, shared) for n, _, shared in segs]
    assert names_and_shared == [(None, True), ("a", False)]
    leftover_stmts = segs[0][1]
    assert any(isinstance(s, ast.Expr) for s in leftover_stmts)


def test_leftover_statements_after_dispatch_are_not_shared():
    """Trailing code AFTER the if/elif chain is NOT unconditionally shared
    (an earlier branch may have already returned) -- only genuinely-shared
    PRE-dispatch code gets shared=True (P0-1 fix)."""
    handler = _handler(
        "def call_tool(name, args):\n"
        "    if name == 'a':\n"
        "        return 1\n"
        "    log_call(name)\n"
    )
    segs = dispatch_segments(handler)
    names_and_shared = [(n, shared) for n, _, shared in segs]
    assert names_and_shared == [("a", False), (None, False)]


def test_no_dispatch_shape_falls_back_to_whole_body():
    handler = _handler(
        "def call_tool(name, args):\n"
        "    return _DISPATCH[name](args)\n"
    )
    segs = dispatch_segments(handler)
    assert len(segs) == 1
    name, stmts, shared = segs[0]
    assert name is None
    assert stmts == handler.body
    assert shared is False


# --------------------------------------------------------------------- #
# P1 fix: same-discriminant-across-the-chain requirement
# --------------------------------------------------------------------- #
def test_mismatched_discriminant_link_and_rest_of_chain_tag_none():
    """`elif arguments.get('mode') == 'delete_everything':` compares a
    DIFFERENT expression than the chain's `name ==` links -- must not
    fabricate a root for a tool that was never registered."""
    handler = _handler(
        "def call_tool(name, arguments):\n"
        "    if name == 'safe_tool':\n"
        "        return 1\n"
        "    elif arguments.get('mode') == 'delete_everything':\n"
        "        return 2\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _, _ in segs]
    assert names == ["safe_tool", None]


def test_mismatch_propagates_to_all_later_links():
    """Once the chain's discriminant breaks, every subsequent link tags
    None even if a later link happens to compare the original discriminant
    again -- chain integrity, once broken, is never partially trusted."""
    handler = _handler(
        "def call_tool(name, arguments):\n"
        "    if name == 'a':\n"
        "        return 1\n"
        "    elif arguments.get('mode') == 'b':\n"
        "        return 2\n"
        "    elif name == 'c':\n"
        "        return 3\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _, _ in segs]
    assert names == ["a", None, None]


def test_first_param_preferred_over_earlier_unrelated_if():
    """An earlier top-level `if` comparing some OTHER variable to a string
    literal must not be mistaken for the dispatch chain when a later `if`
    chain discriminates on the handler's first parameter (refuter A's P3)."""
    handler = _handler(
        "def call_tool(name, arguments):\n"
        "    if arguments.get('debug') == 'on':\n"
        "        log_debug()\n"
        "    if name == 'search_knowledge':\n"
        "        return 1\n"
        "    elif name == 'dump_config':\n"
        "        return 2\n"
    )
    segs = dispatch_segments(handler)
    names_and_shared = [(n, shared) for n, _, shared in segs]
    # the debug-check if is ordinary shared pre-dispatch code (runs before
    # the REAL dispatch chain), not itself a dispatch link.
    assert names_and_shared == [(None, True), ("search_knowledge", False), ("dump_config", False)]


def test_no_first_param_falls_back_to_first_candidate():
    """A handler with no plain positional first parameter (e.g. **kwargs
    only) keeps the previous first-if-found behavior rather than crashing."""
    handler = _handler(
        "def call_tool(**kwargs):\n"
        "    if kwargs.get('name') == 'a':\n"
        "        return 1\n"
        "    elif kwargs.get('name') == 'b':\n"
        "        return 2\n"
    )
    segs = dispatch_segments(handler)
    names = [n for n, _, _ in segs]
    assert names == ["a", "b"]
