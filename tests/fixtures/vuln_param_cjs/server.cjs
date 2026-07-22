// Vulnerable fixture: .cjs (explicit CommonJS) param-injection sinks --
// same risk profile as vuln_param_js, proving .cjs collection parity.
const { exec, spawn } = require('child_process');
const fs = require('fs');
const axios = require('axios');

function runCmd(userArg) {
  exec(`ls ${userArg}`);                             // shell injection
}

function runSpawn(userArg) {
  spawn(userArg, [], { shell: true });               // shell injection
}

function evaluate(expr) {
  return eval(expr);                                 // code eval
}

function fetchUrl(url) {
  return axios.get(url);                             // SSRF
}

function readFile(name) {
  return fs.readFileSync(name, 'utf8');               // path traversal
}

module.exports = { runCmd, runSpawn, evaluate, fetchUrl, readFile };
