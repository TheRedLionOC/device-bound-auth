/**
 * Database adapter for MySQL with the `mysql2` package, which the project installs itself
 * (`npm install mysql2`); this library does not depend on it:
 *   import mysql from 'mysql2/promise';
 *   import { mysql2Adapter } from 'device-bound-auth/server/adapters/mysql2';
 *   const db = mysql2Adapter(mysql.createPool(process.env.DATABASE_URL));
 *   configureAuth({ database: () => db })
 *
 * Pass a pool from 'mysql2/promise' (not the callback API). Create it once at startup.
 * Tables: schema/mysql.sql.
 */
export function mysql2Adapter(pool) {
  const query = async (connection, { sql, params }) => (await connection.execute(sql, params))[0];

  return {
    first: async (statement) => (await query(pool, statement))[0] ?? null,
    all: (statement) => query(pool, statement),
    run: (statement) => query(pool, statement),
    // One transaction on one connection: all or nothing.
    batch: async (statements) => {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        for (const statement of statements) await query(connection, statement);
        await connection.commit();
      } catch (err) {
        await connection.rollback().catch(() => {});
        throw err;
      } finally {
        connection.release();
      }
    },
  };
}
