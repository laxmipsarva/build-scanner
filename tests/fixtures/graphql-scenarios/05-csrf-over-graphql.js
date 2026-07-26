// Scenario: Performing CSRF exploits over GraphQL.
// CSRF prevention is explicitly turned off, so a plain HTML form on an attacker's site can
// trigger a state-changing GraphQL mutation using the victim's session cookie, with no
// preflight required.
import depthLimit from "graphql-depth-limit";

const server = new ApolloServer({
  typeDefs,
  resolvers,
  csrfPrevention: false,
  validationRules: [depthLimit(5)],
});
