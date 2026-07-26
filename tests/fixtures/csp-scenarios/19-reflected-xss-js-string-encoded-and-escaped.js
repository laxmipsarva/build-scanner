// Scenario: Reflected XSS into a JavaScript string with angle brackets and double quotes
// HTML-encoded and single quotes escaped — still bypassable via an escape sequence the
// encoder doesn't account for.
app.get("/greet", (req, res) => {
  const name = encodeAngleDoubleQuotesEscapeSingleQuote(req.query.name);
  res.send(`<script>var name = '${name}';</script>`);
});
