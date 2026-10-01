/**
 * Database adapter for Bun.SQL (Bun's built-in client, no driver to install). One
 * adapter for SQLite, PostgreSQL and MySQL; the URL picks the database:
 *   import { SQL } from 'bun';
 *   import { bunSqlAdapter } from 'device-bound-auth/server/adapters/bun-sql';
 *   const db = bunSqlAdapter(new SQL('sqlite://data/app.db'));   // or postgres://, mysql://
 *   configureAuth({ database: () => db })
 *
 * Create it once at startup (it holds the connection pool), not per request.
 * Tested with SQLite, PostgreSQL 18 and MySQL 8.0 (tables: schema/ at the package root). MySQL 8 needs TLS: mysql://user:pass@host/db?ssl=require
 * Only runs on Bun; not used by the Cloudflare Worker.
 */
export function bunSqlAdapter(sql) {
  // PostgreSQL numbers its placeholders ($1, $2...); SQLite and MySQL use `?`.
  // The auth module's SQL never has a `?` inside a quoted string, so a plain
  // replace is enough.
  const numbered = sql.options?.adapter === 'postgres';
  const toDialect = (text) => {
    if (!numbered) return text;
    let index = 0;
    return text.replace(/\?/g, () => `$${++index}`);
  };
  const query = (client, { sql: text, params }) => client.unsafe(toDialect(text), params);

  return {
    first: async (statement) => (await query(sql, statement))[0] ?? null,
    all: async (statement) => [...(await query(sql, statement))],
    run: (statement) => query(sql, statement),
    // One transaction: all or nothing.
    batch: (statements) =>
      sql.begin(async (tx) => {
        for (const statement of statements) await query(tx, statement);
      }),
  };
}
