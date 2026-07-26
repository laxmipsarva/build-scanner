// Scenario: Reflected XSS into attribute with angle brackets HTML-encoded.
// < and > are encoded but the double quote that delimits the attribute is not.
app.get("/search", (req, res) => {
  const term = htmlEncodeAngleBracketsOnly(req.query.search);
  res.send(`<input type="text" value="${term}">`);
});
