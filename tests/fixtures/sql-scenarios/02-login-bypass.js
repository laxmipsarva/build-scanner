// Scenario: SQL injection vulnerability allowing login bypass.
// Username/password are concatenated directly into the query, so a username of
// `administrator'--` bypasses the password check entirely.
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const sql =
    "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  db.query(sql, (err, rows) => {
    if (rows && rows.length > 0) res.send("Welcome");
    else res.status(401).send("Invalid credentials");
  });
});
