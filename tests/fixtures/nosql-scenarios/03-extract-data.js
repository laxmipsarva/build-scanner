// Scenario: Exploiting NoSQL injection to extract data.
// The stock-check feature builds a $where clause by concatenating the raw storeId, so an
// attacker can replace it with a boolean expression (e.g. this.password[0]=='a') and use the
// in-stock/out-of-stock response as an oracle to extract another user's password one char at a time.
app.post("/product/stock", async (req, res) => {
  const { productId, storeId } = req.body;
  const stock = await Stock.find({
    productId,
    $where: "this.storeId == '" + storeId + "'",
  });
  res.json({ inStock: stock.length > 0 });
});
