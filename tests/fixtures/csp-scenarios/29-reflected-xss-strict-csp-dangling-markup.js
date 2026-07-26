// Scenario: Reflected XSS protected by very strict CSP, with dangling markup attack.
// script-src is strictly nonce-based (no unsafe-inline/eval, no wildcard) so classic script
// injection is blocked — but img-src is left wildcarded, so a dangling, unterminated
// attribute injected via the reflected XSS point can still exfiltrate page data to any
// attacker-controlled host via an auto-issued image request.
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'nonce-r4nd0m'; img-src *",
  );
  next();
});

app.get("/search", (req, res) => {
  const term = req.query.search;
  res.send(`<section>Results for: ${term}<img src="`);
});
