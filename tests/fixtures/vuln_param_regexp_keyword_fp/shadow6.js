// Round-3 N-vote P0-C repro (shadow6): keyword-preceded regex literals.
// `return /^{$/.test(x)` -- "return" is alnum, not a symbol, so the
// original regex-context heuristic (preceding-symbol-only) never
// recognized this as a regex opener. Its embedded `{`/`}` leaked into
// the brace-based scope walk as REAL braces, merging spans across two
// such literals -- and a real cp.exec(cmd) shell-injection sink
// elsewhere in the file vanished (0 findings) as a result.
const cp = require("child_process");

function checkOpenBrace(x) {
  return /^{$/.test(x);
}

function checkCloseBrace(y) {
  return /^}$/.test(y);
}

function runCommand(cmd) {
  return cp.exec(cmd);
}
