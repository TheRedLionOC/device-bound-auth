/**
 * Database adapter for PostgreSQL with the `pg` package (node-postgres), which the project
 * installs itself (`npm install pg`); this library does not depend on it:
 *   import pg from 'pg';
 *   import { pgAdapter } from 'device-bound-auth/server/adapters/pg';
 *   const db = pgAdapter(new pg.Pool({ connectionString: process.env.DATABASE_URL }));
 *   configureAuth({ database: () => db })
 *
 * Pass a Pool (recommended: transactions get their own connection) or a single Client.
 * Create it once at startup, not per request. Tables: schema/postgres.sql.
 */
export function pgAdapter(pool) {
  // PostgreSQL numbers its placeholders ($1, $2...). The auth module's SQL never has a `?`
  // inside a quoted string, so a plain replace is enough.
  const toDialect = (text) => {
    let index = 0;
    return text.replace(/\?/g, () => `$${++index}`);
  };
  const query = (client, { sql, params }) => client.query(toDialect(sql), params);

  return {
    first: async (statement) => (await query(pool, statement)).rows[0] ?? null,
    all: async (statement) => (await query(pool, statement)).rows,
    run: (statement) => query(pool, statement),
    // One transaction on one connection: all or nothing.
    batch: async (statements) => {
      // A Pool lends a dedicated connection (it has totalCount); a Client is one already.
      const isPool = 'totalCount' in pool;
      const client = isPool ? await pool.connect() : pool;
      try {
        await client.query('BEGIN');
        for (const statement of statements) await query(client, statement);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        if (isPool) client.release();
      }
    },
  };
}
