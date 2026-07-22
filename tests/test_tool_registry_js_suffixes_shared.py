"""Regression: tool_registry._JS_SUFFIXES must stay identical to
js_util.JS_SUFFIXES -- it was a private duplicate constant that could
silently drift out of sync (e.g. one gaining .cjs support and the other
not); now it's the same object, not a copy."""
from mcp_scanner import js_util, tool_registry


def test_tool_registry_js_suffixes_is_the_shared_constant():
    assert tool_registry._JS_SUFFIXES is js_util.JS_SUFFIXES
