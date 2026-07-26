// Scenario: Exploiting NoSQL operator injection to extract unknown fields.
// The account lookup spreads the entire raw query string into the filter, so operators such as
// foo[$regex]=^bar let an attacker probe for field names/values that aren't exposed anywhere in
// the app's own UI or docs, enumerating the schema blind rather than reading known columns.
app.get("/account/lookup", async (req, res) => {
  const account = await Account.findOne({ ...req.query });
  res.json(account);
});
