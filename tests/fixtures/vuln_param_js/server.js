// Vulnerable fixture: JS/TS param-injection sinks parity with sinks.py.
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

function makeFn(body) {
  return new Function(body);                         // code eval
}

function fetchUrl(url) {
  return axios.get(url);                             // SSRF
}

function readFile(name) {
  return fs.readFileSync(name, 'utf8');               // path traversal
}
