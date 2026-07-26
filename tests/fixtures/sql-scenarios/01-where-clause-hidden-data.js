// Scenario: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data.
// A category filter is concatenated straight into the WHERE clause, so an attacker can
// append `' OR released = 0--` (or similar) to bypass the "released = 1" restriction and
// see unreleased/hidden products.
app.get("/products", (req, res) => {
  const category = req.query.category;
  const sql = `SELECT * FROM products WHERE category = '${category}' AND released = 1`;
  db.query(sql, (err, rows) => res.json(rows));
});
