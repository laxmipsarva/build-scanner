// Scenario: Stored XSS into anchor href attribute with double quotes HTML-encoded.
// Double quotes are encoded, but the value is placed unquoted inside href, leaving an
// event-handler-style attribute breakout available.
app.get("/profile", (req, res) => {
  const website = htmlEncodeDoubleQuotesOnly(user.website);
  res.send(`<a href=${website}>Visit website</a>`);
});
