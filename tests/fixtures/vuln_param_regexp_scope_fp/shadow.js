// Round-2 N-vote P0-2 repro: _js_regexp_var_names was FILE-WIDE with no
// scoping. A RegExp variable declared in ONE function must not demote a
// receiver of the SAME NAME resolving to a real child_process binding in
// a DIFFERENT, unrelated function.
const cp = require("child_process");

function safeSearch(text) {
  // Local shadow: within THIS function only, `cp` is a RegExp, not the
  // outer child_process module object.
  const cp = /foo/g;
  return cp.exec(text);
}

function runCommand(userInput) {
  // No local `cp` declared here -- this `cp` resolves (real JS closure
  // rules) to the OUTER module-level `const cp = require("child_process")`.
  // Must stay flagged as a real shell-injection sink.
  return cp.exec(userInput);
}

function parsePage(body) {
  const cursor = /\d+/g;
  return cursor.exec(body);
}

function fetchNext(userInput) {
  // Local, function-scoped child_process module binding named `cursor`
  // -- entirely unrelated to parsePage's local regex of the same name.
  // Same dot-receiver shape as parsePage's cursor.exec() -- must stay
  // flagged as a real shell-injection sink.
  const cursor = require("child_process");
  return cursor.exec(userInput);
}

// Control: a module-level regex used inside a NESTED function (real JS
// closure -- genuinely visible everywhere) must still demote correctly --
// scoping must not regress the ancestor-scope case the original fix
// already covered (HTML_COMMENT_RE-style module-level regex vars).
const GLOBAL_RE = /pattern/g;

function useGlobal(text) {
  return GLOBAL_RE.exec(text);
}
