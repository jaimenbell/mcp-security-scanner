// Vulnerable fixture: a string literal containing '//' must not swallow the
// sink call that follows it on the same line (P1a regression -- js_util's
// comment-tail stripper was not string-aware).
const { exec } = require('child_process');

function runCmd(cmd) {
  console.log("audit // trail"); exec(cmd);
}
