// Scenario: Finding and exploiting an unused API endpoint.
// A legacy password-reset route was superseded by /api/v2/reset-password but was never
// removed or gated — it's unreachable from the app's own UI, but still fully live for
// anyone who finds it (e.g. via a leaked API spec or a wordlist scan).
// deprecated: superseded by /api/v2/reset-password, remove after Q3 migration
router.post("/api/reset-password", (req, res) => {
  return resetPasswordLegacy(req.body.email);
});
