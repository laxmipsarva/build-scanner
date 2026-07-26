const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
});

const resolvers2 = {
  Mutation: {
    ping: (parent, args) => {
      return exec(`ping -c 1 ${args.host}`);
    },
  },
};
