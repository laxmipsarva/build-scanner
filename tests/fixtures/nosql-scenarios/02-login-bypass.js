// Scenario: Exploiting NoSQL operator injection to bypass authentication.
// Credentials go straight from req.body into findOne, so a password of { "$ne": "invalid" }
// matches any document with that username regardless of the real password, bypassing login.
app.post("/login", async (req, res) => {
  const user = await User.findOne(req.body);
  if (!user) return res.status(401).send("Invalid credentials");
  res.json({ token: issueToken(user) });
});
