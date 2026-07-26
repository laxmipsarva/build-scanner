// Scenario: Finding a hidden GraphQL endpoint.
// A legacy, undocumented endpoint is left mounted alongside the main API and isn't linked
// from anywhere in the app, but is still fully functional and unprotected. Discovering it is
// a recon/enumeration technique (wordlist-guessing paths), not a static code pattern.
app.use("/graphql", graphqlHTTP({ schema, graphiql: false }));
app.use("/graphql/v1", graphqlHTTP({ schema, graphiql: true }));
