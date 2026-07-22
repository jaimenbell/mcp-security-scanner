// Vulnerable fixture: a real secret-named argument must still be flagged
// (paired with clean_secret_log_boundary_js, which proves the word-boundary
// guard rejects glued substrings).
function debug(password) {
  logger.log('debug', password);
}
