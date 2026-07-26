// Scenario: Reflected XSS with AngularJS sandbox escape without strings.
// No CSP is present; the payload escapes the (pre-1.6) AngularJS expression sandbox using
// only property-access chains, without needing any string literals in the payload itself.
app.get("/search", (req, res) => {
  const term = req.query.search;
  res.send(`<div ng-app ng-csp>Results for: ${term}</div>`);
});
