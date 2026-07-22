// Vulnerable fixture: .cts (explicit-CommonJS TypeScript) -- same grammar
// as .ts, proving .cts collection parity.
import { exec } from 'child_process';

export function runCmd(userArg: string) {
  eval(userArg);                                       // code eval
}
