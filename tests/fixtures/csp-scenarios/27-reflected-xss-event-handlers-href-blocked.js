// Scenario: Reflected XSS with event handlers and href attributes blocked.
// The filter strips on* attributes and href, but not every tag/attribute combination that
// can still execute script (e.g. <svg><animate> with no href).
app.get("/search", (req, res) => {
  const term = stripEventHandlersAndHrefAttributes(req.query.search);
  res.send(`<section>Results for: ${term}</section>`);
});
