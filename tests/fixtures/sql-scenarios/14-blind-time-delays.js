// Scenario: Blind SQL injection with time delays.
// Same tracking-cookie sink; the response looks identical either way, but an attacker
// appends a delay payload (e.g. `xyz'; SELECT SLEEP(5)--` on MySQL, or
// `xyz';WAITFOR DELAY '0:0:5'--` on MSSQL) and measures response latency to confirm the
// query is actually reached and injectable.
app.use((req, res, next) => {
  const trackingId = req.cookies.TrackingId;
  const sql = `SELECT * FROM tracking WHERE id = '${trackingId}'`;
  db.query(sql, () => next());
});
