// Scenario: Visible error-based SQL injection.
// Same tracking-cookie sink, but unlike the "conditional errors" case, the raw database
// error is returned to the client. An attacker can force type-conversion errors (e.g.
// CAST((SELECT password FROM users LIMIT 1) AS int)) whose error message embeds the
// extracted value, so the error text itself becomes the data-exfiltration channel.
app.use((req, res, next) => {
  const trackingId = req.cookies.TrackingId;
  const sql = `SELECT * FROM tracking WHERE id = '${trackingId}'`;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    next();
  });
});
