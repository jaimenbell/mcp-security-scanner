// Vulnerable fixture: .mts (explicit-ESM TypeScript) -- same grammar as
// .ts, proving .mts collection parity.
import { exec } from 'child_process';

export function runCmd(userArg: string) {
  exec(`ls ${userArg}`);                               // shell injection
}
