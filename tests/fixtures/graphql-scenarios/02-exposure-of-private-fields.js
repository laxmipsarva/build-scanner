// Scenario: Accidental exposure of private GraphQL fields.
// The User type's schema accidentally exposes the password field to any client that
// queries for it via introspection.
const typeDefs = `
  type User {
    id: ID!
    username: String!
    password: String!
  }
`;
