// Vulnerable fixture: a destructure-aliased child_process import must still
// be recognized as a shell-injection sink (P1d regression).
const { exec: run } = require('child_process');

function runCmd(userArg) {
  run(`rm -rf ${userArg}`);
}
