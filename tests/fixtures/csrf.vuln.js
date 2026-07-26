app.post("/account/transfer", (req, res) => {
  transferFunds(req.body.to, req.body.amount);
  res.sendStatus(200);
});

app.use((req, res, next) => {
  res.cookie("session", req.sessionId, { sameSite: "none" });
  next();
});
