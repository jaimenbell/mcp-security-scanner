// Vulnerable fixture: a secret-named identifier interpolated inside a
// template literal must still be flagged (P2 regression, adversarial
// verify-pass 2026-07-22 -- _JS_STRING_LITERAL previously stripped the
// ENTIRE template literal, including ${...} interpolations, before the
// secret-name scan ran).
function debug(apiKey) {
  logger.log(`token: ${apiKey}`);
}
