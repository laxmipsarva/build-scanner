app.put("/api/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id);
  user.name = String(req.body.name);
  user.email = String(req.body.email);
  await user.save();
  res.json(user);
});

app.get("/products", async (req, res) => {
  const sort = ALLOWED_SORT_FIELDS.includes(req.query.sort) ? req.query.sort : "default";
  const upstream = await fetch(`http://internal-catalog-api/products?sort=${encodeURIComponent(sort)}`);
  res.json(await upstream.json());
});
