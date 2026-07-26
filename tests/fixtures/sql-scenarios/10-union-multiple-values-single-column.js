// Scenario: SQL injection UNION attack, retrieving multiple values in a single column.
// Same concatenated sink; when only one usable output column exists, the attacker
// concatenates several values into it, e.g.
// `' UNION SELECT username || ':' || password, NULL FROM users--`.
app.get("/search", (req, res) => {
  const term = req.query.term;
  const sql = `SELECT name FROM products WHERE category = '${term}'`;
  db.query(sql, (err, rows) => res.json(rows));
});
