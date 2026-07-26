app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  next();
});

app.use(
  cors({
    origin: "*",
    credentials: true,
  }),
);
