// Scenario: Reflected XSS with some SVG markup allowed.
// The filter permits <svg> and its animation elements, which can execute script via
// onload/onbegin handlers.
app.get("/search", (req, res) => {
  const term = allowSvgMarkup(req.query.search);
  res.send(`<section>Results for: ${term}</section>`);
});
