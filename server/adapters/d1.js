/**
 * Database adapter for Cloudflare D1 (SQLite). Gives a D1 binding the interface the
 * auth module uses (see ../store.js):
 *   import { d1Adapter } from 'device-bound-auth/server/adapters/d1';
 *   configureAuth({ database: (env) => d1Adapter(env.DB) })
 */
export function d1Adapter(d1) {
  const prepare = ({ sql, params }) => d1.prepare(sql).bind(...params);
  return {
    first: (statement) => prepare(statement).first(),
    all: async (statement) => (await prepare(statement).all()).results,
    run: (statement) => prepare(statement).run(),
    // D1 runs a batch as one transaction: all or nothing.
    batch: (statements) => d1.batch(statements.map(prepare)),
  };
}
