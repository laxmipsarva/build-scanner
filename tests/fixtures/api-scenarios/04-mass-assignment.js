// Scenario: Exploiting a mass assignment vulnerability.
// The entire request body is passed straight into the user update call, so a client can set
// fields never exposed in the edit-profile form (e.g. { "isAdmin": true }).
app.put("/api/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id);
  await user.update(req.body);
  res.json(user);
});
