// Scenario: Exploiting server-side parameter pollution in a REST URL.
// The client-supplied user ID is spliced directly into the path of an internal REST
// request. Injecting an extra path segment or query string (e.g. `123/orders?admin=true`)
// pollutes the backend request with parameters the client was never meant to control.
app.get("/api/profile/:userId", async (req, res) => {
  const upstream = await fetch(`http://internal-user-api/users/${req.params.userId}/profile`);
  res.json(await upstream.json());
});
