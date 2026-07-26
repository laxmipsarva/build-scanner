// Scenario: Reflected XSS into a JavaScript string with single quote and backslash escaped.
// Escaping ' and \ isn't enough on its own if the escaper mishandles other terminator
// sequences the browser still treats as ending the string.
app.get("/greet", (req, res) => {
  const name = escapeSingleQuoteAndBackslash(req.query.name);
  res.send(`<script>var name = '${name}';</script>`);
});
