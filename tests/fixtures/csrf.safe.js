import csurf from "csurf";

const csrfProtection = csurf({ cookie: true });

app.post("/account/transfer", csrfProtection, (req, res) => {
  transferFunds(req.body.to, req.body.amount);
  res.sendStatus(200);
});
