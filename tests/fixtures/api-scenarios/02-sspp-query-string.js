// Scenario: Exploiting server-side parameter pollution in a query string.
// The server splices the client's sort parameter straight into the query string of an
// internal backend request. Injecting an extra `&`-delimited parameter (e.g.
// `sort=price%26fields=*,ssn`, decoded to `sort=price&fields=*,ssn`) pollutes the backend
// request with a parameter the client was never meant to control.
app.get("/products", async (req, res) => {
  const upstream = await fetch(`http://internal-catalog-api/products?sort=${req.query.sort}`);
  res.json(await upstream.json());
});
