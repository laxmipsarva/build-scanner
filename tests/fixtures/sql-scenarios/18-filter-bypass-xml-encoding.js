// Scenario: SQL injection with filter bypass via XML encoding.
// The app tries to defend against SQL injection with a denylist filter that strips
// quote characters (and separately rejects raw SQL keywords), then still concatenates
// the "sanitized" value into the query. If the request body arrives as XML and the
// parser XML-decodes entities (e.g. `&#x27;` -> `'`, `&#x53;ELECT` -> `SELECT`) *after*
// this filter runs, the attacker's encoded payload sails through the check and is
// decoded back into a live quote/keyword by the time it reaches the query.
function sanitize(input) {
  const noQuotes = input.replace(/'/g, "");
  if (/(select|union|insert|update|delete|drop)/i.test(noQuotes)) {
    throw new Error("Rejected: SQL keyword detected");
  }
  return noQuotes;
}

app.post("/search", (req, res) => {
  const term = sanitize(req.body.term); // req.body was parsed from XML upstream
  const sql = `SELECT * FROM products WHERE name LIKE '%${term}%'`;
  db.query(sql, (err, rows) => res.json(rows));
});
