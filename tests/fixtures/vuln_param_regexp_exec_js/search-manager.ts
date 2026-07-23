// Fixture: anonymized from wonderwhy-er/DesktopCommanderMCP's
// src/search-manager.ts -- a `new RegExp(...)` variable's .exec() call in a
// file that also imports child_process (execSync used elsewhere).
import { execSync } from "child_process";

function extractText(xml: string): string[] {
  const wtRe = new RegExp("<w:t(?:\\s[^>]*)?>([^<]*)</w:t>", "g");
  const out: string[] = [];
  let m;
  while ((m = wtRe.exec(xml)) !== null) {
    out.push(m[1]);
  }
  return out;
}

function ripgrepVersion(systemRg: string): string {
  // Real sink -- must still flag.
  return execSync(`${systemRg} --version`, { encoding: "utf-8" }).trim();
}
