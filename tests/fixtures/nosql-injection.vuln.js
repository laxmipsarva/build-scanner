app.post("/login", async (req, res) => {
  const user = await User.findOne(req.body);
  res.json(user);
});

function findByFilter(collection, filter) {
  return collection.find({ $where: `this.name == '${filter}'` });
}
