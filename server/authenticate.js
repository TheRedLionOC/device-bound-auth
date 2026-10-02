import { authConfig, database, jwtSecret } from './config.js';
import { sessionKeyThumbprint, verifyDpopProof } from './dpop.js';
import { AuthError } from './errors.js';
import { verifyJwt } from './jwt.js';
import { findSessionWithUser, touchSession } from './store.js';

/**
 * 401 responses carry a code so the app knows what to do with its local data:
 *  - session_expired: the token is authentic (this server issued it) but no longer
 *    accepted: it timed out, or it is not used the way this server requires (DPoP scheme,
 *    bound to a key). Nothing suspicious happened: the app keeps local data and the same
 *    user logs in again.
 *  - session_revoked: the session was closed on purpose (logout, closed by an admin,
 *    password/role change, user deactivated or deleted) or the token is not authentic
 *    (forged, or signed with a previous secret). The app deletes its local data.
 */
const expired = (message) => new AuthError(401, message, { code: 'session_expired' });
const revoked = (message) => new AuthError(401, message, { code: 'session_revoked' });
const invalidProof = (message) => new AuthError(401, message, { code: 'invalid_dpop_proof' });

/**
 * Resolves the user and session from the DPoP-bound token. Both are re-read from
 * the database on every request, so revoked sessions and deactivated users
 * lose access immediately even if their token has not expired yet.
 * The request must also carry a DPoP proof from the device the session was created on.
 */
export async function authenticate(request, env) {
  const secret = jwtSecret(env);
  const db = database(env);

  const [, scheme, token] = (request.headers.get('Authorization') ?? '').match(/^(\w+) (.+)$/) ?? [];
  if (!token) throw new AuthError(401, 'Missing authentication token');

  // Authenticity first: a token this server did not issue is refused whatever the scheme.
  const { payload, error } = await verifyJwt(token, secret);
  if (error === 'expired') throw expired('Session expired');
  if (error || !payload.sub || !payload.sid) throw revoked('Invalid token');

  // An authentic token is only accepted bound to a key and sent with the DPoP scheme.
  if (scheme.toLowerCase() !== 'dpop') throw expired('Authorization must use the DPoP scheme');
  if (!payload.cnf?.jkt) throw expired('Token is not bound to a DPoP key');

  const now = Date.now();
  const row = await findSessionWithUser(db, payload.sid, payload.sub);

  if (!row || row.revoked_at) throw revoked('Session was closed');
  if (!row.active || row.deleted_at) throw revoked('User is inactive or deleted');
  if (row.expires_at <= now) throw expired('Session expired');
  if (!row.public_key) throw expired('Session is not bound to a DPoP key');

  // The device proves it holds the key the session and the token are bound to.
  const jkt = await sessionKeyThumbprint(row.public_key);
  if (payload.cnf.jkt !== jkt) throw invalidProof('Token is bound to another key');
  const proof = await verifyDpopProof(request, env, { accessToken: token });
  if (proof.jkt !== jkt) throw invalidProof('DPoP key does not belong to this session');

  // For reads (e.g. an automatic sync every few minutes), last_seen_at is only written
  // when older than sessions.lastSeenResolutionMs, to avoid a write on every request.
  // Writes (the user saved or deleted something) always update it.
  const isWrite = !['GET', 'HEAD'].includes(request.method);
  if (isWrite || now - row.last_seen_at > authConfig().sessions.lastSeenResolutionMs) {
    await touchSession(db, payload.sid, now);
  }

  return { user: await loadUser(env, row), session: { id: payload.sid, jkt } };
}

/** Public user fields plus whatever the project adds (hooks.loadUserContext). */
export async function loadUser(env, row) {
  const user = { id: row.id, username: row.username, name: row.name, role: row.role };
  return { ...user, ...(await authConfig().hooks.loadUserContext(env, user)) };
}
