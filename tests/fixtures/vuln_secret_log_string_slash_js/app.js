// Vulnerable fixture: a string literal containing '//' must not swallow the
// secret-named argument that follows it on the same line (P1a regression).
function debug(password) {
  logger.log("Debug info // details", password);
}
