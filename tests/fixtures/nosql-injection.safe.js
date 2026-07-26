app.post("/login", async (req, res) => {
  const username = String(req.body.username);
  const user = await User.findOne({ username });
  res.json(user);
});
