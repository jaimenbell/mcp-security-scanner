// Clean fixture: .cjs equivalent done safely.
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const BASE_DIR = path.resolve('/srv/data');            // containment hint

function runCmd() {
  execFile('ls', ['-la']);                             // argv, no shell
}

function evaluate() {
  return eval('1 + 1');                                // constant arg
}

function fetchUrl() {
  return axios.get('https://api.github.com/meta');     // constant URL
}

function readFile(name) {
  const target = path.resolve(BASE_DIR, name);          // containment check
  return fs.readFileSync(target, 'utf8');
}

module.exports = { runCmd, evaluate, fetchUrl, readFile };
