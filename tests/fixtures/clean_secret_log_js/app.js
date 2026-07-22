// Clean fixture: no secret-named values ever logged (message prose only).
function login() {
  console.log('login attempted, token required but not shown');
}

function status() {
  console.log('ok');
}
