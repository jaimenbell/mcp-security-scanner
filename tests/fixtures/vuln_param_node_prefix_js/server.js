// Vulnerable fixture: the Node 16+ 'node:child_process' import prefix must
// be recognized just like the bare 'child_process' form (P1c regression).
import { exec } from 'node:child_process';

function runCmd(userArg) {
  exec(`rm -rf ${userArg}`);
}
