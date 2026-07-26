// Scenario: SQL injection attack, querying the database type and version on MySQL and
// Microsoft SQL Server. Same concatenated sink as the Oracle case; on MySQL/MSSQL an
// attacker fingerprints the engine with `' UNION SELECT @@version--` instead.
function searchProducts(pool, name) {
  const sql = "SELECT * FROM products WHERE name = '" + name + "'";
  return pool.query(sql);
}

module.exports = { searchProducts };
