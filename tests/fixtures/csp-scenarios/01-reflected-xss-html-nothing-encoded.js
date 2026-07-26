// Scenario: Reflected XSS into HTML context with nothing encoded.
// The search term is echoed straight into the page body with no encoding at all.
app.get("/search", (req, res) => {
  const term = req.query.search;
  res.send(`<section>Results for: ${term}</section>`);
});
