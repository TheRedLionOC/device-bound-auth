/**
 * Storage of the auth module: every SQL query lives here. It knows no database driver:
 * a query is plain data, { sql, params }, run through a small database interface that
 * an adapter provides (see adapters/):
 *
 *   db.first(statement)   → first row or null
 *   db.all(statement)     → array of rows
 *   db.run(statement)     → runs a write
 *   db.batch(statements)  → runs several writes in one transaction (all or nothing)
 *
 * The SQL is portable (SQLite, PostgreSQL, MySQL): only `?` placeholders (adapters
 * renumber them when the database needs $1, $2...), no database-specific functions.
 * Expected column types: ids and text TEXT/VARCHAR, timestamps (ms since epoch) INTEGER
 * or BIGINT, `active` INTEGER 0/1, case-insensitive username (see schema/ at the package root).
 *
 * Functions named *Statement return a statement instead of running it, so it can go in
 * one atomic batch with others (including the project's hook statements, see config.js).
 */
import { AuthError } from './errors.js';

const PUBLIC_USER_COLUMNS = 'id, username, name, role, active, created_at, updated_at';

/** A query as plain data. Also exported for project hooks (see index.js). */
export const statement = (sql, ...params) => ({ sql, params });

// Timestamps are ms since epoch. PostgreSQL drivers (Bun.SQL, pg) return BIGINT as a
// string to avoid losing precision; ms timestamps fit a JS number, so convert them back.
const TIMESTAMP_COLUMNS = ['created_at', 'updated_at', 'last_seen_at', 'expires_at', 'revoked_at', 'deleted_at'];

function normalize(row) {
  if (!row) return null;
  for (const column of TIMESTAMP_COLUMNS) {
    if (typeof row[column] === 'string') row[column] = Number(row[column]);
  }
  return row;
}

const first = async (db, query) => normalize(await db.first(query));
const all = async (db, query) => (await db.all(query)).map(normalize);

/** Runs statements atomically (all or nothing), turning a duplicate username into a 409. */
export async function runBatch(db, statements) {
  try {
    await db.batch(statements);
  } catch (err) {
    // SQLite: "UNIQUE constraint failed: users.username", PostgreSQL: "duplicate key value
    // violates unique constraint "users_username_key"", MySQL: "Duplicate entry ... 'users.username'"
    const message = String(err?.message);
    if (/unique|duplicate/i.test(message) && message.includes('username')) {
      throw new AuthError(409, 'Duplicate value for users.username', { code: 'duplicate' });
    }
    throw err;
  }
}

// --- Sessions ---------------------------------------------------------------

/** The session and its user, as needed on every authenticated request. */
export function findSessionWithUser(db, sessionId, userId) {
  return first(
    db,
    statement(
      `SELECT u.id, u.username, u.name, u.role, u.active, u.deleted_at,
              s.last_seen_at, s.public_key, s.revoked_at, s.expires_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = ? AND s.user_id = ?`,
      sessionId,
      userId,
    ),
  );
}

export function touchSession(db, sessionId, now) {
  return db.run(statement('UPDATE sessions SET last_seen_at = ? WHERE id = ?', now, sessionId));
}

/** Inserts a session and deletes sessions that expired before `deleteBefore`. */
export function createSession(db, session, deleteBefore) {
  return db.batch([
    // Uses idx_sessions_expires_at, so it only reads the rows it deletes.
    statement('DELETE FROM sessions WHERE expires_at < ?', deleteBefore),
    statement(
      `INSERT INTO sessions (id, user_id, user_agent, public_key, created_at, last_seen_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      session.id,
      session.userId,
      session.userAgent,
      session.publicKey,
      session.createdAt,
      session.createdAt,
      session.expiresAt,
    ),
  ]);
}

export function extendSession(db, sessionId, expiresAt) {
  return db.run(statement('UPDATE sessions SET expires_at = ? WHERE id = ?', expiresAt, sessionId));
}

// Revoking also moves expires_at to now (unless already earlier), so cleanup only has
// to look at expires_at (indexed) instead of scanning the table for revoked rows.
const REVOKE = 'UPDATE sessions SET revoked_at = ?, expires_at = CASE WHEN expires_at < ? THEN expires_at ELSE ? END';

export function revokeSession(db, sessionId, now) {
  return db.run(statement(`${REVOKE} WHERE id = ? AND revoked_at IS NULL`, now, now, now, sessionId));
}

/** Revokes every active session of a user, optionally keeping one (e.g. the current one). */
export function revokeUserSessionsStatement(userId, now, exceptSessionId = null) {
  const where = 'WHERE user_id = ? AND revoked_at IS NULL';
  return exceptSessionId
    ? statement(`${REVOKE} ${where} AND id <> ?`, now, now, now, userId, exceptSessionId)
    : statement(`${REVOKE} ${where}`, now, now, now, userId);
}

export function listActiveSessions(db, userId, now) {
  return all(
    db,
    statement(
      `SELECT id, user_agent, created_at, last_seen_at, expires_at
       FROM sessions
       WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
       ORDER BY last_seen_at DESC`,
      userId,
      now,
    ),
  );
}

export async function sessionBelongsToUser(db, sessionId, userId) {
  return Boolean(await first(db, statement('SELECT id FROM sessions WHERE id = ? AND user_id = ?', sessionId, userId)));
}

// --- Users ------------------------------------------------------------------

/** An active user with their password hash, for login. */
export function findLoginUser(db, username) {
  return first(
    db,
    statement(
      `SELECT id, username, name, role, password_hash, password_salt
       FROM users WHERE username = ? AND active = 1`,
      username,
    ),
  );
}

/** A user that is not deleted (public columns only), or null. */
export function findUser(db, id) {
  return first(db, statement(`SELECT ${PUBLIC_USER_COLUMNS} FROM users WHERE id = ? AND deleted_at IS NULL`, id));
}

export function listUsers(db) {
  return all(
    db,
statement(`SELECT ${PUBLIC_USER_COLUMNS} FROM users WHERE deleted_at IS NULL ORDER BY name`));
}

export function insertUserStatement(user, now) {
  return statement(
    `INSERT INTO users (id, username, name, password_hash, password_salt, role, active, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    user.id,
    user.username,
    user.name,
    user.passwordHash,
    user.passwordSalt,
    user.role,
    user.active,
    now,
    now,
  );
}

export function updateUserStatement(user, now) {
  return statement(
    'UPDATE users SET username = ?, name = ?, role = ?, active = ?, updated_at = ? WHERE id = ?',
    user.username,
    user.name,
    user.role,
    user.active,
    now,
    user.id,
  );
}

export function updatePasswordStatement(userId, hash, salt) {
  return statement('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?', hash, salt, userId);
}

/** Soft delete: the row stays, but inactive and with a freed (renamed) username. */
export function deleteUserStatement(userId, { now, deletedBy, username }) {
  return statement(
    'UPDATE users SET deleted_at = ?, deleted_by = ?, active = 0, updated_at = ?, username = ? WHERE id = ?',
    now,
    deletedBy,
    now,
    username,
    userId,
  );
}
