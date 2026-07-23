// Round-3 N-vote P0-C repro: braces in this file do NOT balance (the
// `broken` function and its `if` are never closed). The scope walker
// must FAIL CLOSED here -- discard ALL scope info for the whole file --
// so every .exec receiver becomes unresolvable, including the
// shadowRegex() case below that WOULD otherwise legitimately demote in
// a well-formed file. Over-flagging everything is the safe direction
// when scope info can't be trusted; masking is not.
const cp = require("child_process");

function broken(x) {
  if (x) {
    return 1;

function shadowRegex() {
  const cp = /test/;
  return cp.exec("x");
}

function runCommand(cmd) {
  return cp.exec(cmd);
}
