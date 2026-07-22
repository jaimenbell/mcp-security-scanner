"""Shared JS/TS text-scanning helpers.

The scanner has no JS/TS AST -- every JS/TS-facing detector operates on raw
line text with the same line-based regex approach ``job_hazards.py`` already
uses for cron/systemd/CI/wrapper files. These helpers are the one shared
implementation of that approach (comment stripping + best-effort call-argument
extraction) so multiple detectors don't each carry a slightly different copy.

Honest limits, stated once here and inherited by every detector that imports
this module: line-based, not a real JS/TS parser.

* A call whose arguments span multiple lines is only scanned up to the end of
  the line the call starts on -- a false negative, not a false positive
  (consistent with this repo's over-flag-never-under-flag philosophy applying
  to sinks it DOES see).
* Comment stripping is a same-line ``// ...`` heuristic (plus whole-line
  ``/* ... */`` / ``*`` continuation lines); it does not track a multi-line
  ``/* ... */`` block comment that opens on one line and closes on another --
  code inside such a block can still be scanned (a possible false positive,
  the same direction this scanner already accepts elsewhere).
* ``is_const_arg`` recognizes a plain quoted string literal only. String
  concatenation (``'a' + b``) and any template literal containing ``${`` are
  correctly treated as non-constant.
"""

from __future__ import annotations

import re

JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}


def is_comment_line(line: str) -> bool:
    """True for a whole-line '//' comment or a '/* ... */' block line."""
    s = line.lstrip()
    if not s:
        return False
    return s.startswith("//") or s.startswith("/*") or s.startswith("*")


def _find_line_comment_start(line: str) -> int:
    """Index of a trailing '// comment''s opening slash, string-aware, or
    -1 if there isn't one.

    A '//' preceded by whitespace is a trailing comment; one glued to other
    characters (e.g. the '//' in 'http://...') is left alone -- UNLESS
    either '//' sits inside a string/template literal, in which case it is
    never a comment regardless of what precedes it (P1a fix: the previous
    plain regex approach had no notion of string literals, so
    ``console.log("audit // trail"); exec(cmd)`` had everything from the
    ``// `` inside the string onward deleted, including the real code after
    the string literal closed)."""
    in_str: str | None = None
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/" and i > 0 and line[i - 1].isspace():
            return i
        i += 1
    return -1


def code_part(line: str) -> str:
    """The line with any trailing '// comment' stripped (URLs and string
    literal contents -- including one that itself contains '//' -- untouched)."""
    idx = _find_line_comment_start(line)
    if idx == -1:
        return line
    return line[:idx]


def first_call_arg(text: str, open_paren_idx: int) -> str:
    """Best-effort text of the first top-level argument after the '(' at
    ``open_paren_idx``.

    Balances nested ``()``/``[]``/``{}`` and skips over string/template
    literals so a comma or paren inside a string doesn't cut the argument
    short. Line-scoped: ``text`` is expected to be a single source line.
    """
    depth = 0
    i = open_paren_idx + 1
    start = i
    n = len(text)
    in_str: str | None = None
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0 and c == ")":
                return text[start:i]
            depth -= 1
        elif c == "," and depth == 0:
            return text[start:i]
        i += 1
    return text[start:i]


_CONST_STR = re.compile(r"""^(['"`])((?:\\.|(?!\1).)*)\1$""", re.DOTALL)


def is_const_arg(arg: str) -> bool:
    """True if ``arg`` text is a plain string literal with no interpolation
    and no concatenation (the whole trimmed argument is exactly one quoted
    literal)."""
    arg = arg.strip()
    m = _CONST_STR.match(arg)
    if not m:
        return False
    quote, body = m.group(1), m.group(2)
    if quote == "`" and "${" in body:
        return False
    return True
