// Clean fixture: names that merely CONTAIN a secret-vocabulary substring
// glued inside a longer, unrelated word must not be flagged (cheap-win
// regression -- secret_handling's JS log check previously lacked the
// word-boundary guard secret_leak_response._name_looks_secret already has).
function checkKey(apiKeyValidator) {
  console.log('valid:', apiKeyValidator.isValid);
}

function showConfig(tokenizerConfig) {
  console.log('version:', tokenizerConfig.version);
}
