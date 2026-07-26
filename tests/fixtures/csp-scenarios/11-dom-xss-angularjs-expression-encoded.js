// Scenario: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded.
// Angle brackets and double quotes are encoded, but AngularJS still evaluates {{ }}
// expressions once it parses the resulting DOM inside an ng-app scope.
app.get("/search", (req, res) => {
  const term = htmlEncodeAngleBracketsAndQuotes(req.query.search);
  res.send(`<div ng-app>Search results for ${term}</div>`);
});
