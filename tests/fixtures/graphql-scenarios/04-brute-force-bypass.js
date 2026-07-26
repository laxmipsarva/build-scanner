// Scenario: Bypassing GraphQL brute force protections.
// Login attempts are rate-limited per HTTP request, but GraphQL's built-in query batching
// lets an attacker send hundreds of login mutations inside a single HTTP request/array body,
// exhausting a password list without ever tripping the per-request counter. Detecting this
// requires reasoning about where a rate limiter counts vs. where batched operations are
// executed — not a pattern a single-file regex scan can see.
app.use(rateLimit({ windowMs: 60_000, max: 5 }));
app.post("/graphql", graphqlHTTP({ schema, rootValue: resolvers }));

const resolvers = {
  login: async ({ username, password }) => {
    const user = await User.findOne({ username });
    return user && (await user.checkPassword(password)) ? issueToken(user) : null;
  },
};
