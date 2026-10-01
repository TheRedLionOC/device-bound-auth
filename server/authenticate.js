import { authConfig, database, jwtSecret } from './config.js';
import { verifyDeviceProof } from './device-proof.js';
import { AuthError } from './errors.js';
import { verifyJwt } from './jwt.js';
import { findSessionWithUser, touchSession } from './store.js';

/**
 * 401 responses carry a code so the app knows what to do with its local data:
 *  - session_expired: the session simply timed out. The app keeps local data so
 *    unsynced changes are sent after the same user logs in again.
 *  - session_revoked: the session was closed on purpose (logout, closed by an admin,
 *    password/role change, user deactivated or deleted, secret rotated). The app
 *    deletes all local data, since that is usually why it was closed.
 */
const expired = (message) => new AuthError(401, message, { code: 'session_expired' });
const revoked = (message) => new AuthError(401, message, { code: 'session_revoked' });

/**
 * Resolves the user and session from the Bearer token. Both are re-read from
 * the database on every request, so revoked sessions and deactivated users
 * lose access immediately even if their token has not expired yet.
 * The request must also be signed by the device the session was created on.
 */
export async function authenticate(request, env) {
  const secret = jwtSecret(env);
  const db = database(env);

  const header = request.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) throw new AuthError(401, 'Missing authentication token');

  const { payload, error } = await verifyJwt(token, secret);
  if (error === 'expired') throw expired('Session expired');
  if (error || !payload.sub || !payload.sid) throw revoked('Invalid token');

  const now = Date.now();
  const row = await findSessionWithUser(db, payload.sid, payload.sub);

  if (!row || row.revoked_at) throw revoked('Session was closed');
  if (!row.active || row.deleted_at) throw revoked('User is inactive or deleted');
  if (row.expires_at <= now) throw expired('Session expired');
  // Sessions created before device binding existed have no key: force a new login.
  if (!row.public_key) throw expired('Session is not bound to a device');

  await verifyDeviceProof(request, new URL(request.url), payload.sid, row.public_key);

  // For reads (e.g. an automatic sync every few minutes), last_seen_at is only written
  // when older than sessions.lastSeenResolutionMs, to avoid a write on every request.
  // Writes (the user saved or deleted something) always update it.
  const isWrite = !['GET', 'HEAD'].includes(request.method);
  if (isWrite || now - row.last_seen_at > authConfig().sessions.lastSeenResolutionMs) {
    await touchSession(db, payload.sid, now);
  }

  return { user: await loadUser(env, row), session: { id: payload.sid } };
}

/** Public user fields plus whatever the project adds (hooks.loadUserContext). */
export async function loadUser(env, row) {
  const user = { id: row.id, username: row.username, name: row.name, role: row.role };
  return { ...user, ...(await authConfig().hooks.loadUserContext(env, user)) };
}
