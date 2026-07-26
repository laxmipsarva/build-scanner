// Scenario: Reflected XSS into HTML context with all tags blocked except custom ones.
// The filter allows unrecognized/custom tag names through, and the browser still fires
// events registered on them via a CSS animation trick.
app.get("/search", (req, res) => {
  const term = allowOnlyCustomTags(req.query.search);
  res.send(`<section>Results for: ${term}</section>`);
});
