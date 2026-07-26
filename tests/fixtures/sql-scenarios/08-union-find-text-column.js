// Scenario: SQL injection UNION attack, finding a column containing text.
// Same concatenated sink; once the column count is known, the attacker finds a
// string-typed column with `' UNION SELECT 'a', NULL, NULL--` and varying the position.
app.get("/search", (req, res) => {
  const term = req.query.term;
  const sql = `SELECT id, name, price FROM products WHERE category = '${term}'`;
  db.query(sql, (err, rows) => res.json(rows));
});
