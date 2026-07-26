const allowlist = ["https://example.com"];

app.use(
  cors({
    origin: (origin, callback) => {
      callback(null, allowlist.includes(origin));
    },
    credentials: true,
  }),
);
