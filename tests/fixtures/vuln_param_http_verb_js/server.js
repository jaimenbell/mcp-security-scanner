// Fixture: a JS/TS ssrf sink whose HTTP verb IS stated lexically.
//
// `axios.post(...)` names a state-changing verb just as plainly as
// `requests.post(...)` does. It still must NOT escalate: the verb
// calibration is scoped to the Python AST path only. See the SCOPE section of
// param_injection.py's module docstring for the two reasons (the sibling
// `fetch(url, {method})` shape needs a JS parser this scanner does not have,
// and `ssrf` is a capped class on every unanalysable file, so an escalation
// here would be reverted by grading.py and could never reach a report).

const axios = require("axios");

async function push(url, body) {
  return axios.post(url, body);
}

module.exports = { push };
