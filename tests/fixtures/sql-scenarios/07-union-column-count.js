// Scenario: SQL injection UNION attack, determining the number of columns returned by
// the query. Same concatenated sink; an attacker probes the column count with
// `' ORDER BY 1--`, `' ORDER BY 2--`, ... or `' UNION SELECT NULL,NULL,NULL--`.
app.get("/search", (req, res) => {
  const term = req.query.term;
  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${term}%'`;
  db.query(sql, (err, rows) => res.json(rows));
});
