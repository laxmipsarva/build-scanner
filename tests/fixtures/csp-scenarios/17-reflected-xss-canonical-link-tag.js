// Scenario: Reflected XSS in canonical link tag.
// The request path is reflected unencoded into a <link rel="canonical"> href, which some
// browsers/extensions (e.g. AMP viewers) will parse as executable markup.
app.get("*", (req, res) => {
  res.send(`<link rel="canonical" href="https://example.com${req.originalUrl}">`);
});
