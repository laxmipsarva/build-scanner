// Scenario: Reflected XSS into HTML context with most tags and attributes blocked.
// The denylist strips most dangerous tags/attributes but misses less common ones
// (e.g. <body onresize>, <svg>), so it's still bypassable.
app.get("/search", (req, res) => {
  const term = stripMostDangerousTagsAndAttributes(req.query.search);
  res.send(`<section>Results for: ${term}</section>`);
});
