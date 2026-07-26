// Scenario: Reflected XSS protected by CSP, with CSP bypass.
// The policy has no unsafe-inline/unsafe-eval and no bare wildcard, but it allowlists a
// third-party host whose own hosted scripts can be abused to run arbitrary attacker JS,
// bypassing the CSP entirely without violating any directive. build-scanner's csp rule only
// checks for unsafe keywords/wildcards/disabled CSP, so it has no way to know this specific
// allowlisted host is a known bypass gadget — that requires an external bypass-domain list.
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' https://accounts.google.com",
  );
  next();
});

app.get("/search", (req, res) => {
  const term = req.query.search;
  res.send(`<section>Results for: ${term}</section>`);
});
