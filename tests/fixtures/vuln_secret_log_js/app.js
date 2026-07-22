// Vulnerable fixture: secret-named value logged in JS (secret-in-log parity).
function login(apiKey) {
  console.log('using key', apiKey);
}

function auth(token) {
  logger.info('token=' + token);
}
