// Scenario: Detecting NoSQL injection.
// The category filter is handed straight from the query string into the MongoDB filter, so a
// value like `category[$ne]=` (parsed by Express into { $ne: "" }) returns every product instead
// of a 404 — the first sign the backend is interpreting operators from user input.
app.get("/product/category", async (req, res) => {
  const products = await Product.find(req.query);
  res.json(products);
});
