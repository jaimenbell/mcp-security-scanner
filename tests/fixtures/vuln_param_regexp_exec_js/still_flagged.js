// Fixture: shapes that must STILL flag as shell-injection after the
// RegExp/child_process receiver-resolution fix -- proving the fix only
// demotes a CONFIDENTLY-resolved RegExp receiver, never a real sink or an
// unresolvable one.
const child_process = require("child_process");
const { exec: run } = require("child_process");

function direct(cmd) {
  child_process.exec(cmd); // receiver literally child_process -- real sink
}

function alias(cmd) {
  run(cmd); // destructured alias of exec -- real sink
}

function bare(cmd) {
  exec(cmd); // bare call, no receiver at all -- real sink shape
}

function unresolved(thing, str) {
  // "thing" is not resolvable as a RegExp variable anywhere in this file --
  // unresolvable receiver must stay flagged (over-flag-safe direction).
  thing.exec(str);
}
