// Scenario: Accessing private GraphQL posts.
// The blogPost query returns any post by ID with no check that it has been published —
// introspection reveals an "isPublished" field, but no resolver enforces it, so an attacker
// can request unpublished/private posts directly by ID. This is an authorization-logic bug
// in the resolver body, not a config pattern a static regex scan can reliably detect.
const resolvers = {
  Query: {
    blogPost: (parent, { id }) => posts.find((p) => p.id === id),
  },
};
