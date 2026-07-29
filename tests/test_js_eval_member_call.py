"""JS `eval` is a bare global -- `redis.eval(...)` is a different function.

FROM THE 2026-07-29 HELD-OUT MEASUREMENT, class (i). The only four P0s in the
entire 58-finding sample were `mcp/oauth/refresh-lock.ts:216,238,246,338` in
neondatabase/mcp-server-neon, and all four were:

    redis.eval(HEARTBEAT_LUA, { keys: [lkey], arguments: [owner, ...] })

That is node-redis's EVAL command -- server-side Lua, with the script defined
as a module-level `const` template literal and keys/args passed as separate
parameters (i.e. correctly parameterized). It is not JavaScript `eval()` at
all. The detector's pattern was `\\beval\\s*\\(`, and `\\b` matches happily
after a `.`, so every `.eval(` method call in the ecosystem read as the global.

THE FIX is the lookbehind this same module already uses for the identical
problem on `exec` (`_JS_BARE_EXEC = r"(?<![\\w$.])exec(?:Sync)?\\s*\\("`), so
this is bringing one pattern in line with its sibling rather than inventing a
rule. `(?<![\\w$.])` also covers optional chaining (`redis?.eval(`), because
the character immediately before `eval` there is still `.`.

RECALL IS NOT TRADED AWAY: the global `eval(...)`, `await eval(...)`,
`(0, eval)(...)`-adjacent bare forms and `window.eval` are pinned below. Only
a member call on a receiver stops matching -- and `window.eval`/`globalThis.eval`
are deliberately kept OUT of the finding set as a stated, accepted false
negative rather than a special case, since re-admitting any `X.eval(` would
re-admit `redis.eval(` with it.
"""
from pathlib import Path

import pytest

from mcp_scanner.detectors import ParamInjectionDetector
from mcp_scanner.detectors.base import RepoContext, SourceFile


def _evals(text: str, rel: str = "src/lock.ts"):
    sf = SourceFile(path=Path(rel), rel=rel, text=text, tree=None,
                    lines=text.splitlines())
    ctx = RepoContext(root=Path("."), files=[sf], tracked=set(), is_git=False)
    return [f for f in ParamInjectionDetector().run(ctx)
            if f.vuln_class == "code-eval"]


# --- the false positives that must stop -----------------------------------
@pytest.mark.parametrize("line", [
    "await withTimeout(redis.eval(HEARTBEAT_LUA, { keys: [lkey], arguments: [owner] }), 'hb');",
    "await redis.eval(RELEASE_LUA, { keys: [key], arguments: [owner] });",
    "const r = await client.eval(script, keys, args);",
    "await redis?.eval(LUA, opts);",
    "return this.redis.eval(LUA_SCRIPT, { keys });",
    "db.eval(fn, param);",
])
def test_member_eval_calls_are_not_javascript_eval(line):
    assert _evals(line) == [], (
        f"{line!r} is a method named eval on a receiver, not the JS global"
    )


# --- the recall half: the real global must still fire ---------------------
@pytest.mark.parametrize("line", [
    "eval(userSuppliedCode);",
    "const out = eval(payload);",
    "await eval(req.body.script);",
    "  eval (spaced);",
    "if (x) { eval(y); }",
    "foo(eval(bar));",
])
def test_bare_global_eval_still_flags(line):
    hits = _evals(line)
    assert len(hits) == 1, (
        f"{line!r} is the real JS global eval and must still be flagged "
        f"(got {hits})"
    )


def test_constant_argument_is_still_exempt_as_before():
    """Unchanged behaviour, pinned so the lookbehind edit did not disturb it."""
    assert _evals("eval('2 + 2');") == []


def test_new_function_is_untouched_by_this_change():
    """`new Function(...)` is a separate pattern and a separate finding; it
    must keep firing at full strength."""
    hits = [f for f in _evals("const g = new Function('return ' + x);")]
    assert len(hits) == 1
    assert "Function" in hits[0].title


def test_the_measured_neon_lines_produce_zero_eval_findings():
    """End-to-end on the actual shape from mcp-server-neon's refresh-lock.ts,
    module-level Lua consts included -- the exact file that produced 4 of the
    58 false positives, and 4 of the 4 P0s."""
    src = """
const HEARTBEAT_LUA = `
  if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('PEXPIRE', KEYS[1], ARGV[2])
  end
  return 0
`;
export async function heartbeat(redis, lkey, owner) {
  return withTimeout(
    redis.eval(HEARTBEAT_LUA, {
      keys: [lkey],
      arguments: [owner, String(LOCK_TTL_MS)],
    }),
    'heartbeat',
  );
}
"""
    assert _evals(src, rel="mcp/oauth/refresh-lock.ts") == []
