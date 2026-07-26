// Scenario: Stored XSS into HTML context with nothing encoded.
// A comment is saved as-is and rendered back into the page with no encoding.
app.post("/comment", (req, res) => {
  comments.push(req.body.comment);
  res.redirect("/comments");
});

app.get("/comments", (req, res) => {
  const html = comments.map((c) => `<p>${c}</p>`).join("");
  res.send(`<div id="comments">${html}</div>`);
});
