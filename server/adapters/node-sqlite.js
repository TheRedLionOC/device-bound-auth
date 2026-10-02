/**
 * Database adapter for SQLite with Node's built-in `node:sqlite` (Node 22.5+, no package
 * to install):
 *   import { DatabaseSync } from 'node:sqlite';
 *   import { nodeSqliteAdapter } from 'device-bound-auth/server/adapters/node-sqlite';
 *   const db = nodeSqliteAdapter(new DatabaseSync('data/app.db'));   // once, at startup
 *   configureAuth({ database: () => db })
 *
 * node:sqlite is synchronous, like better-sqlite3 and bun:sqlite: SQLite runs inside the
 * process, so the auth module's indexed queries take microseconds. A batch runs start to
 * finish without yielding, so no other request can interleave with its transaction.
 * Tables: schema/sqlite.sql.
 */
export function nodeSqliteAdapter(database) {
  const run = ({ sql, params }) => database.prepare(sql).run(...params);

  return {
    first: async ({ sql, params }) => database.prepare(sql).get(...params) ?? null,
    all: async ({ sql, params }) => database.prepare(sql).all(...params),
    run: async (statement) => run(statement),
    // One transaction: all or nothing.
    batch: async (statements) => {
      database.exec('BEGIN');
      try {
        for (const statement of statements) run(statement);
        database.exec('COMMIT');
      } catch (err) {
        database.exec('ROLLBACK');
        throw err;
      }
    },
  };
}
