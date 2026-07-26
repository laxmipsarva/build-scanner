// Scenario: SQL injection attack, listing the database contents on non-Oracle databases.
// Same concatenated sink; on MySQL/Postgres/MSSQL the attacker enumerates schema via
// `' UNION SELECT table_name, NULL FROM information_schema.tables--`.
function searchProducts(connection, name) {
  const sql = `SELECT * FROM products WHERE name = '${name}'`;
  return connection.query(sql);
}

module.exports = { searchProducts };
