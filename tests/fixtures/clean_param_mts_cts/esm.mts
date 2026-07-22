// Clean fixture: .mts equivalent done safely.
import { execFile } from 'child_process';

export function runCmd() {
  execFile('ls', ['-la']);                             // argv, no shell
}
