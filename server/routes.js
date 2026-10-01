import { loadUser } from './authenticate.js';
import { authConfig, database } from './config.js';
import { normalizePublicKey } from './device-proof.js';
import { AuthError, json, readJson } from './errors.js';
import { hashPassword, verifyPassword } from './password.js';
import { refreshSession, startSession } from './sessions.js';
import { findLoginUser, revokeSession } from './store.js';

// Used to spend the same time hashing when the user does not exist,
// so response timing does not reveal valid usernames.
let dummyCredentials;

/** Login, current user, refresh and logout under `prefix` (the browser module's authPath). */
export function registerAuthRoutes(router, { prefix = '/auth' } = {}) {
  router.post(`${prefix}/login`, login, { auth: 'public' });
  // The other three are available to every logged-in role (router default: 'any').
  router.get(`${prefix}/me`, ({ user }) => json({ user }));
  router.post(`${prefix}/refresh`, refresh);
  router.post(`${prefix}/logout`, logout);
}

async function login({ request, env }) {
  const { username, password, public_key: publicKeyJwk } = await readJson(request);
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    throw new AuthError(400, 'Username and password are required');
  }
  await authConfig().loginRateLimit?.({ request, env, username });
  const publicKey = await normalizePublicKey(publicKeyJwk);

  const user = await findLoginUser(database(env), username.trim());

  dummyCredentials ??= await hashPassword(crypto.randomUUID());
  const { hash, salt } = user
    ? { hash: user.password_hash, salt: user.password_salt }
    : dummyCredentials;
  const valid = await verifyPassword(password, hash, salt);
  if (!user || !valid) throw new AuthError(401, 'Invalid username or password');

  const token = await startSession(env, user, request, publicKey);
  return json({ token, user: await loadUser(env, user) });
}

/** Extends the current session and returns a new token (sliding expiration). */
async function refresh({ env, user, session }) {
  return json({ token: await refreshSession(env, user, session.id), user });
}

/** Revokes the current session so its token stops working everywhere. */
async function logout({ env, session }) {
  await revokeSession(database(env), session.id, Date.now());
  return json({ ok: true });
}
