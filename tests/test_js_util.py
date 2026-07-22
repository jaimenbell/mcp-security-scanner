from mcp_scanner.js_util import (
    is_comment_line,
    code_part,
    first_call_arg,
    is_const_arg,
)


def test_full_line_comment_detected():
    assert is_comment_line("  // a note")
    assert is_comment_line("* continuation of a block comment")
    assert not is_comment_line("const x = 1;")


def test_code_part_strips_trailing_comment_but_not_url():
    assert code_part("exec(cmd); // danger") == "exec(cmd); "
    # 'http://' must survive -- the '//' there isn't preceded by whitespace
    line = "axios.get('http://example.com')"
    assert code_part(line) == line


def test_code_part_preserves_double_slash_inside_string_literal():
    # P1a regression: a '//' inside a string literal must never be treated
    # as a comment tail -- the sink call after it must survive.
    line = 'console.log("audit // trail"); exec(cmd)'
    assert code_part(line) == line


def test_code_part_preserves_secret_arg_after_string_containing_slash_slash():
    # P1a regression: the same bug silently dropped a secret-named argument
    # that came after a "// "-bearing string literal.
    line = 'logger.log("Debug info // details", password)'
    assert code_part(line) == line


def test_first_call_arg_balances_nested_parens_and_strings():
    text = "fetch(buildUrl(a, b), { method: 'GET' })"
    idx = text.index("(")
    assert first_call_arg(text, idx) == "buildUrl(a, b)"


def test_first_call_arg_stops_at_top_level_comma():
    text = "spawn(cmd, args, { shell: true })"
    idx = text.index("(")
    assert first_call_arg(text, idx) == "cmd"


def test_is_const_arg_true_for_plain_string_literal():
    assert is_const_arg("'ls -la'")
    assert is_const_arg('"https://api.github.com/meta"')


def test_is_const_arg_false_for_variable_or_interpolated_template():
    assert not is_const_arg("userArg")
    assert not is_const_arg("`ls ${userArg}`")
    assert not is_const_arg("'a' + userArg")
