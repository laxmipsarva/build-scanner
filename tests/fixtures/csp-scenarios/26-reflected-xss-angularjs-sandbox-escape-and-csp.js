// Scenario: Reflected XSS with AngularJS sandbox escape and CSP.
// The CSP permits 'unsafe-eval', which both weakens XSS protection generally and is exactly
// what the AngularJS sandbox-escape payload relies on to invoke the Function constructor.
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-eval'",
  );
  next();
});

app.get("/search", (req, res) => {
  const term = req.query.search;
  res.send(`<div ng-app>Results for: ${term}</div>`);
});
