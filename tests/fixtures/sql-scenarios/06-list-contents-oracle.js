// Scenario: SQL injection attack, listing the database contents on Oracle.
// Same concatenated sink; on Oracle there's no built-in information_schema, so the
// attacker enumerates schema via `' UNION SELECT table_name, NULL FROM all_tables--`.
const oracledb = require("oracledb");

async function searchProducts(connection, name) {
  const sql = `SELECT * FROM products WHERE name = '${name}'`;
  return connection.execute(sql);
}

module.exports = { searchProducts };
