// Scenario: CORS vulnerability with basic origin reflection.
// The server reflects whatever Origin header the browser sends and marks the response as
// credentialed, so any malicious site can read authenticated responses cross-origin.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});
