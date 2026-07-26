function getUser(db, userId) {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

function search(db, term) {
  return db.query("SELECT * FROM products WHERE name = '" + term + "'");
}
