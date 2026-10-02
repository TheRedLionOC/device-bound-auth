/**
 * User administration (admin only): list, create, update, soft delete, and the
 * sessions of each user. Roles and project-specific side effects come from
 * configureAuth() (see config.js).
 */
import { authConfig, database } from './config.js';
import * as store from './store.js';
import { AuthError, json, readJson } from './errors.js';
import { checkNewPassword, hashPassword } from './password.js';

const ID_PATTERN = /^[A-Za-z0-9-]{1,64}$/;

/** User administration under `prefix`, for the 'admin' access level. */
export function registerUserRoutes(router, { prefix = '/users' } = {}) {
  router.get(prefix, listUsers, { auth: 'admin' });
  router.post(prefix, createUser, { auth: 'admin' });
  router.put(`${prefix}/:id`, updateUser, { auth: 'admin' });
  router.delete(`${prefix}/:id`, deleteUser, { auth: 'admin' });
  router.get(`${prefix}/:id/sessions`, listUserSessions, { auth: 'admin' });
  router.post(`${prefix}/:id/sessions/revoke`, revokeUserSessions, { auth: 'admin' });
  router.post(`${prefix}/:id/sessions/:sessionId/revoke`, revokeUserSession, { auth: 'admin' });
}

async function listUsers({ env }) {
  return json({ users: await store.listUsers(database(env)) });
}

async function createUser({ request, env }) {
  const { hooks } = authConfig();
  const db = database(env);
  const data = validateUser(await readJson(request));
  await hooks.validateUserChange(env, { data, previous: null });
  const { hash, salt } = await hashPassword(checkNewPassword(data.password));
  const id = crypto.randomUUID();
  const now = Date.now();

  await store.runBatch(db, [
    store.insertUserStatement({ id, ...data, passwordHash: hash, passwordSalt: salt }, now),
    ...(await hooks.userStatements(env, { user: { id, ...data }, previous: null, now })),
  ]);
  return json({ user: await findUser(db, id) }, 201);
}

async function updateUser({ request, env, params, user: currentUser, session }) {
  const { hooks } = authConfig();
  const db = database(env);
  const id = assertId(params.id);
  const data = validateUser(await readJson(request));
  const previous = await findUser(db, id);

  if (id === currentUser.id && (data.role !== 'admin' || !data.active)) {
    throw new AuthError(400, 'You cannot remove your own admin access');
  }
  await hooks.validateUserChange(env, { data, previous });

  const now = Date.now();
  const statements = [
    store.updateUserStatement({ id, ...data }, now),
    ...(await hooks.userStatements(env, { user: { id, ...data }, previous, now })),
  ];
  if (data.password) {
    const { hash, salt } = await hashPassword(checkNewPassword(data.password));
    statements.push(store.updatePasswordStatement(id, hash, salt));
  }
  // A new password, a deactivated account or a different role close every open session
  // (except the admin's own current one), so devices log in again with the new
  // permissions and reload only the data they are allowed to see.
  if (data.password || !data.active || data.role !== previous.role) {
    statements.push(store.revokeUserSessionsStatement(id, now, id === currentUser.id ? session.id : null));
  }

  await store.runBatch(db, statements);
  return json({ user: await findUser(db, id) });
}

/**
 * Soft delete: the row stays (history keeps the name) but the user can no longer
 * log in, their sessions are closed and their username is freed for reuse.
 * Deactivating instead is done with PUT active = 0.
 */
async function deleteUser({ env, params, user: currentUser }) {
  const { hooks } = authConfig();
  const db = database(env);
  const id = assertId(params.id);
  if (id === currentUser.id) throw new AuthError(400, 'You cannot delete your own user');
  const user = await findUser(db, id);
  await hooks.validateUserDelete(env, user);

  const now = Date.now();
  const username = authConfig().users.deletedUsername(user.username, { id, now });
  await store.runBatch(db, [
    store.deleteUserStatement(id, { now, deletedBy: currentUser.id, username }),
    store.revokeUserSessionsStatement(id, now),
    ...(await hooks.userDeleteStatements(env, { user, deletedBy: currentUser, now })),
  ]);
  return json({ ok: true });
}

async function listUserSessions({ env, params, session }) {
  const db = database(env);
  const id = assertId(params.id);
  await findUser(db, id);
  const sessions = await store.listActiveSessions(db, id, Date.now());
  return json({ sessions: sessions.map((s) => ({ ...s, current: s.id === session.id })) });
}

async function revokeUserSessions({ env, params }) {
  const db = database(env);
  const id = assertId(params.id);
  await findUser(db, id);
  await db.run(store.revokeUserSessionsStatement(id, Date.now()));
  return json({ ok: true });
}

async function revokeUserSession({ env, params }) {
  const db = database(env);
  const id = assertId(params.id);
  const sessionId = assertId(params.sessionId);
  if (!(await store.sessionBelongsToUser(db, sessionId, id))) throw new AuthError(404, 'Session not found');
  await store.revokeSession(db, sessionId, Date.now());
  return json({ ok: true });
}

async function findUser(db, id) {
  const user = await store.findUser(db, id);
  if (!user) throw new AuthError(404, 'User not found');
  return user;
}

/** Validates and normalizes a user from the request body. Unknown fields are dropped. */
function validateUser(input) {
  const { roles, users } = authConfig();
  const source = input && typeof input === 'object' ? input : {};
  const text = (value) => (typeof value === 'string' ? value.trim() : value);
  const errors = {};

  const checkText = (field, { required, max }) => {
    const value = text(source[field]);
    if (value === undefined || value === null || value === '') {
      if (required) errors[field] = 'is required';
      return null;
    }
    if (typeof value !== 'string') errors[field] = 'must be text';
    else if (value.length > max) errors[field] = `must be at most ${max} characters`;
    return value;
  };

  const data = {
    username: checkText('username', { required: true, max: users.usernameMaxLength }),
    name: checkText('name', { required: true, max: users.nameMaxLength }),
    password: checkText('password', { max: 200 }),
    role: text(source.role) || roles[0],
    active: [undefined, null, '', true, 1, '1', 'true'].includes(source.active) ? 1 : 0,
  };
  if (!roles.includes(data.role)) errors.role = `must be one of: ${roles.join(', ')}`;
  if (![undefined, null, '', true, false, 0, 1, '0', '1', 'true', 'false'].includes(source.active)) {
    errors.active = 'must be a boolean';
  }

  if (Object.keys(errors).length) {
    const summary = Object.entries(errors)
      .map(([field, error]) => `${field} ${error}`)
      .join(', ');
    throw new AuthError(400, `Invalid data: ${summary}`, errors);
  }
  return data;
}

function assertId(id) {
  if (typeof id !== 'string' || !ID_PATTERN.test(id)) throw new AuthError(400, 'Invalid id');
  return id;
}
