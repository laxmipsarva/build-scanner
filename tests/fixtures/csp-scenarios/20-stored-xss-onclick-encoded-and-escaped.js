// Scenario: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded
// and single quotes and backslash escaped — still bypassable via an HTML entity that decodes
// inside the event-handler attribute context before the browser parses it as JS.
app.get("/product", (req, res) => {
  const review = encodeAndEscapeReview(product.review);
  res.send(`<button onclick="reportReview('${review}')">Report</button>`);
});
