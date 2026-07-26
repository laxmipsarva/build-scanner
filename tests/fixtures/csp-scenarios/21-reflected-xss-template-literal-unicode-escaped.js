// Scenario: Reflected XSS into a template literal with angle brackets, single, double quotes,
// backslash and backtick Unicode-escaped — still bypassable if the sink later evaluates the
// string as code (e.g. via eval/Function), since Unicode escapes decode back to their raw
// characters once JS parses them.
app.get("/greet", (req, res) => {
  const name = unicodeEscapeAllSpecialChars(req.query.name);
  res.send(`<script>var greeting = \`Hello, ${name}\`; eval("(" + greeting + ")");</script>`);
});
