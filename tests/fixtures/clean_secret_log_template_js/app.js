// Clean fixture: a glued compound-word interpolation (word-boundary guard
// from the d1c1bb8 fix still applies inside ${...}) and a '${' occurring
// inside a NON-template quoted string (literal text in real JS, never
// interpolation) must both stay quiet.
function checkKey(apiKeyValidator) {
  console.log(`check ${apiKeyValidator.isValid}`);
}

function showPrice(price) {
  console.log("cost is ${price}");
}
