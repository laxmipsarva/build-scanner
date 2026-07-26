app.put("/api/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id);
  await user.update(req.body);
  res.json(user);
});

app.get("/products", async (req, res) => {
  const upstream = await fetch(`http://internal-catalog-api/products?sort=${req.query.sort}`);
  res.json(await upstream.json());
});
