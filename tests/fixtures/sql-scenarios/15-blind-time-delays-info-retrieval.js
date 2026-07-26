// Scenario: Blind SQL injection with time delays and information retrieval.
// Same tracking-cookie sink; here the attacker makes the delay conditional on a
// character of extracted data (e.g. `xyz'; IF (SUBSTRING((SELECT password FROM users
// WHERE username='administrator'),1,1)='a') WAITFOR DELAY '0:0:5'--`), turning response
// latency into a one-bit-at-a-time data exfiltration channel.
app.use((req, res, next) => {
  const trackingId = req.cookies.TrackingId;
  const sql = `SELECT * FROM tracking WHERE id = '${trackingId}'`;
  db.query(sql, () => next());
});
