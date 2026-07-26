// Scenario: SQL injection attack, querying the database type and version on Oracle.
// This is the same underlying sink as every other scenario here — a concatenated WHERE
// clause — but on Oracle it also lets an attacker fingerprint the engine, e.g. by
// appending: ' UNION SELECT banner, NULL FROM v$version--
const oracledb = require("oracledb");

async function searchProducts(connection, name) {
  const sql = `SELECT * FROM products WHERE name = '${name}'`;
  return connection.execute(sql);
}

module.exports = { searchProducts };
