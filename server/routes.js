import { loadUser } from './authenticate.js';
import { authConfig, database } from './config.js';
import { storedPublicKey, verifyDpopProof } from './dpop.js';
import { AuthError, json, readJson } from './errors.js';
import { checkNewPassword, hashPassword, verifyPassword } from './password.js';
import { refreshSession, startSession } from './sessions.js';
import {
  findLoginUser,
  findPasswordHash,
  revokeSession,
  revokeUserSessionsStatement,
  runBatch,
  updatePasswordStatement,
} from './store.js';
import { insertUser, validateUser } from './users.js';

// Used to spend the same time hashing when the user does not exist,
// so response timing does not reveal valid usernames.
let dummyCredentials;

/**
 * Login, sign-up, current user, refresh, logout and password change under `prefix`
 * (the browser module's authPath). Sign-up answers 404 unless signup.enabled.
 */
export function registerAuthRoutes(router, { prefix = '/auth' } = {}) {
  router.post(`${prefix}/login`, login, { auth: 'public' });
  router.post(`${prefix}/register`, register, { auth: 'public' });
  // The rest are available to every logged-in role (router default: 'any').
  router.get(`${prefix}/me`, ({ user }) => json({ user }));
  router.post(`${prefix}/refresh`, refresh);
  router.post(`${prefix}/logout`, logout);
  router.post(`${prefix}/password`, changePassword);
}

/**
 * The device key a new session is bound to: the one in the DPoP proof sent with the request,
 * which also proves the device holds the private key (RFC 9449 §5).
 */
async function deviceKey(request, env) {
  return storedPublicKey((await verifyDpopProof(request, env)).jwk);
}

async function login({ request, env }) {
  // Read from a copy: the DPoP proof check needs the original body (bh).
  const body = await readJson(request.clone());
  const { username, password } = body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    throw new AuthError(400, 'Username and password are required');
  }
  await authConfig().loginRateLimit?.({ request, env, username });
  const publicKey = await deviceKey(request, env);

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

/**
 * Self sign-up (configureAuth signup). Creates the user with signup.role and, unless
 * signup.requireApproval, logs them in on this device like login does. Attempts count
 * against the login rate limit. Note: a taken username answers 409, so sign-up reveals
 * which usernames exist (unavoidable when people pick their own).
 */
async function register({ request, env }) {
  const { signup } = authConfig();
  if (!signup.enabled) throw new AuthError(404, 'Not found');

  const body = await readJson(request.clone());
  const username = typeof body?.username === 'string' ? body.username : '';
  await authConfig().loginRateLimit?.({ request, env, username });
  await signup.verify?.({ request, env, body });
  // Checked before creating the user, so a bad key does not leave an account behind.
  const publicKey = signup.requireApproval ? null : await deviceKey(request, env);

  const data = validateUser({
    username: body.username,
    name: body.name,
    password: body.password,
    role: signup.role,
    active: signup.requireApproval ? 0 : 1,
  });
  const id = await insertUser(env, data);
  if (signup.requireApproval) return json({ pending: true }, 201);

  const user = { id, username: data.username, name: data.name, role: data.role };
  const token = await startSession(env, user, request, publicKey);
  return json({ token, user: await loadUser(env, user) }, 201);
}

/** Extends the current session and returns a new token (sliding expiration). */
async function refresh({ env, user, session }) {
  return json({ token: await refreshSession(env, user, session), user });
}

/** Revokes the current session so its token stops working everywhere. */
async function logout({ env, session }) {
  await revokeSession(database(env), session.id, Date.now());
  return json({ ok: true });
}

/**
 * Changes the logged-in user's own password. Requires the current one (a stolen session
 * alone cannot take over the account) and closes the user's other sessions, keeping
 * this one. Attempts count against the login rate limit, so the current password
 * cannot be guessed through this route either.
 */
async function changePassword({ request, env, user, session }) {
  const { current_password: currentPassword, new_password: newPassword } = await readJson(request);
  if (typeof currentPassword !== 'string' || !currentPassword) {
    throw new AuthError(400, 'The current password is required');
  }
  await authConfig().loginRateLimit?.({ request, env, username: user.username });

  const db = database(env);
  const row = await findPasswordHash(db, user.id);
  // 400, not 401: a 401 would make the browser module end the session.
  if (!row || !(await verifyPassword(currentPassword, row.password_hash, row.password_salt))) {
    throw new AuthError(400, 'The current password is incorrect', { code: 'wrong_password' });
  }

  const { hash, salt } = await hashPassword(checkNewPassword(newPassword));
  const now = Date.now();
  await runBatch(db, [
    updatePasswordStatement(user.id, hash, salt),
    revokeUserSessionsStatement(user.id, now, session.id),
  ]);
  return json({ ok: true });
}
