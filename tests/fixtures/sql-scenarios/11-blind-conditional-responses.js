// Scenario: Blind SQL injection with conditional responses.
// A tracking cookie is concatenated into a query whose result isn't shown to the user,
// but the page renders differently (e.g. a "Welcome back" banner) depending on whether
// the query matched — enough for an attacker to infer true/false one bit at a time via
// payloads like `xyz' AND '1'='1` vs `xyz' AND '1'='2`.
app.use((req, res, next) => {
  const trackingId = req.cookies.TrackingId;
  const sql = `SELECT * FROM tracking WHERE id = '${trackingId}'`;
  db.query(sql, (err, rows) => {
    res.locals.recognizedUser = !!(rows && rows.length);
    next();
  });
});
