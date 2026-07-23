// Fixture: RegExp.exec() calls in a file that ALSO imports child_process
// for a real, legitimate execSync use -- anonymized from GLips/Figma-
// Context-MCP's scripts/scan-hidden-chars.mjs (the exact real-ecosystem
// shape: 3 RegExp .exec() calls + 1 real execSync call, all in one file).
import { execSync } from "node:child_process";

const HTML_COMMENT_RE = /<!--([\s\S]*?)-->/g;
const HIDDEN_REF_LINK_RE = /^\[\/\/\]: #\s*[("](.*?)[)"]\s*$/;

function scanContent(content) {
  const cfPattern = /\p{Cf}/gu;
  let cfMatch;
  while ((cfMatch = cfPattern.exec(content)) !== null) {
    console.log(cfMatch);
  }
  let commentMatch;
  while ((commentMatch = HTML_COMMENT_RE.exec(content)) !== null) {
    console.log(commentMatch);
  }
  let refMatch;
  while ((refMatch = HIDDEN_REF_LINK_RE.exec(content)) !== null) {
    console.log(refMatch);
  }
}

function trackedFiles(extensions) {
  // Real sink -- must still flag.
  const tracked = execSync(`git ls-files -- ${extensions}`, {
    encoding: "utf-8",
  });
  return tracked;
}

module.exports = { scanContent, trackedFiles };
