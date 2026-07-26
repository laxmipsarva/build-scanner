// Scenario: CORS vulnerability with trusted null origin.
// The allowlist treats Origin: null as trusted (to support sandboxed iframes / local files),
// but an attacker can trivially send that exact header from a sandboxed iframe or a data: URL,
// so this "trusted" origin is actually attacker-controlled.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin === "null" || allowlist.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});
