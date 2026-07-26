// Scenario: SQL injection UNION attack, retrieving data from other tables.
// Same concatenated sink; once the vulnerable text column is known, the attacker pulls
// data from another table with `' UNION SELECT username, password FROM users--`.
app.get("/search", (req, res) => {
  const term = req.query.term;
  const sql = `SELECT id, name, price FROM products WHERE name = '${term}'`;
  db.query(sql, (err, rows) => res.json(rows));
});
