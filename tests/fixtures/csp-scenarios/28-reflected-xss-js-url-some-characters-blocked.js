// Scenario: Reflected XSS in a JavaScript URL with some characters blocked.
// The filter blocks a denylist of characters in a javascript: URI but misses alternate
// whitespace/encoding the browser still treats as executable.
app.get("/redirect", (req, res) => {
  const url = blockSomeCharactersInJavascriptUrl(req.query.url);
  res.send(`<a href="${url}">Continue</a>`);
});
