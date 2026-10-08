import { graphqlHTTP } from 'express-graphql';
import { buildSchema } from 'graphql';
import { query } from './db.js';

const schema = buildSchema(`
  type Order { id: Int, user_id: Int, total: Float }
  type Query {
    order(id: Int!): Order
    orders(user_id: Int!): [Order]
  }
`);

const root = {
  order: ({ id }) =>
    query('SELECT * FROM orders WHERE id = $1', [id]).then((r) => r.rows[0]),
  orders: ({ user_id }) =>
    query('SELECT * FROM orders WHERE user_id = $1', [user_id]).then((r) => r.rows),
};

export function registerGraphQL(app) {
  app.use('/graphql', graphqlHTTP({ schema, rootValue: root, graphiql: true }));
}
