app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' *");
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);
