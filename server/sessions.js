import { database, jwtSecret, sessionRetentionMs, sessionTtlMs } from './config.js';
import { signJwt } from './jwt.js';
import { createSession, extendSession } from './store.js';

// Sessions and tokens last configureAuth({ sessions: { ttlDays } }) since the last
// refresh. Expired sessions (revoked ones included, see store.js revokeSession) are
// deleted after sessions.retentionDays, so records that store a session id can still
// be traced to a device for a while.

const MAX_USER_AGENT_LENGTH = 300;

/**
 * Creates a session bound to the device's public key (see device-proof.js)
 * and returns a token for it.
 */
export async function startSession(env, user, request, publicKey) {
  const now = Date.now();
  const session = {
    id: crypto.randomUUID(),
    userId: user.id,
    userAgent: (request.headers.get('User-Agent') ?? '').slice(0, MAX_USER_AGENT_LENGTH) || null,
    publicKey,
    createdAt: now,
    expiresAt: now + sessionTtlMs(),
  };
  await createSession(database(env), session, now - sessionRetentionMs());
  return issueToken(env, user, session.id);
}

/** Extends the session and returns a fresh token for it. */
export async function refreshSession(env, user, sessionId) {
  await extendSession(database(env), sessionId, Date.now() + sessionTtlMs());
  return issueToken(env, user, sessionId);
}

function issueToken(env, user, sessionId) {
  return signJwt({ sub: user.id, sid: sessionId, role: user.role }, jwtSecret(env), Math.floor(sessionTtlMs() / 1000));
}
