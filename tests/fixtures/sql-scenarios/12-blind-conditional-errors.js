// Scenario: Blind SQL injection with conditional errors.
// Same tracking-cookie sink as the conditional-response case, but here the app returns
// a generic 500 only when the injected condition throws (e.g. a CASE WHEN ... THEN
// (1/0) END divide-by-zero trick), letting an attacker infer true/false from the status
// code alone even though no error detail is shown.
app.use((req, res, next) => {
  const trackingId = req.cookies.TrackingId;
  const sql = `SELECT * FROM tracking WHERE id = '${trackingId}'`;
  db.query(sql, (err) => {
    if (err) return res.sendStatus(500);
    next();
  });
});
