// Scenario: Reflected XSS into a JavaScript string with angle brackets HTML encoded.
// Angle brackets are encoded, but the quote that closes the JS string literal is not.
app.get("/greet", (req, res) => {
  const name = htmlEncodeAngleBracketsOnly(req.query.name);
  res.send(`<script>var name = "${name}"; document.write("Hi " + name);</script>`);
});
