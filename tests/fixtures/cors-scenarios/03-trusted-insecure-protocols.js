// Scenario: CORS vulnerability with trusted insecure protocols.
// The allowlist regex trusts both http and https for the domain, so a network attacker who can
// intercept or host plain-http traffic on a trusted subdomain can forge the Origin header and
// receive credentialed cross-origin responses meant only for the secure origin.
const trustedOriginRegex = /^https?:\/\/([a-z0-9-]+\.)?example\.com$/;

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (trustedOriginRegex.test(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});
