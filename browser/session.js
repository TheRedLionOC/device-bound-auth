/**
 * Session lifecycle: login, token refresh, expiry and logout.
 * Project-specific behaviour comes from configureAuth() (config.js).
 */
import { api } from './api.js';
import { authConfig } from './config.js';
import { createDeviceKey } from './device-key.js';
import { clearAuth, readSession, writeDeviceKey, writeSession } from './store.js';

/** { token, issuedAt, user } or null. */
export function getSession() {
  return readSession();
}

/**
 * Logs in with a new device key: the session only accepts requests signed by
 * this browser's private key, which never leaves the device.
 */
export async function login(username, password) {
  const { privateKey, publicJwk } = await createDeviceKey();
  const { token, user } = await api(`${authConfig().authPath}/login`, {
    method: 'POST',
    // The server takes the key from the DPoP proof (proofKey).
    body: { username, password },
    auth: false,
    proofKey: { privateKey, publicJwk },
  });
  await startLocalSession(token, user, { privateKey, publicJwk });
  return user;
}

/**
 * Creates an account (the server must enable signup) and, unless it needs an admin's
 * approval, logs in on this device like login(). Returns { user } or { pending: true }.
 * Errors are ApiError: 404 (sign-up disabled), 409 details.code 'duplicate' (username
 * taken), 400 (invalid data, details.code 'weak_password'), 429 (rate limit).
 */
export async function register({ username, name, password, ...extra }) {
  const { privateKey, publicJwk } = await createDeviceKey();
  const result = await api(`${authConfig().authPath}/register`, {
    method: 'POST',
    // `extra` reaches the server's signup.verify hook (e.g. a CAPTCHA token).
    body: { ...extra, username, name, password },
    auth: false,
    proofKey: { privateKey, publicJwk },
  });
  if (result.pending) return { pending: true };
  await startLocalSession(result.token, result.user, { privateKey, publicJwk });
  return { user: result.user };
}

async function startLocalSession(token, user, deviceKey) {
  // Local data belongs to one user (and scope): start clean when that changes.
  const previous = (await readSession())?.user;
  if (previous && !authConfig().sameScope(previous, user)) await authConfig().onReset();

  await writeDeviceKey(deviceKey);
  await writeSession({ token, issuedAt: Date.now(), user });
}

/** Exchanges the token for a new one when older than refreshAfterMs. Needs a connection. */
export async function refreshTokenIfNeeded() {
  const session = await readSession();
  if (!session?.token || Date.now() - (session.issuedAt ?? 0) < authConfig().refreshAfterMs) return;

  const { token, user } = await api(`${authConfig().authPath}/refresh`, { method: 'POST' });
  await writeSession({ token, issuedAt: Date.now(), user });
}

/**
 * Changes the logged-in user's own password. The server checks the current one and
 * closes the user's other sessions; this one stays open. Errors are ApiError with
 * status 400 and details.code 'wrong_password' or 'weak_password', or 429 (rate limit).
 */
export async function changePassword(currentPassword, newPassword) {
  await api(`${authConfig().authPath}/password`, {
    method: 'POST',
    body: { current_password: currentPassword, new_password: newPassword },
  });
}

/**
 * Called when the API rejects the session.
 *  - Expired (timed out): keep the user and local data, only drop the token, so the
 *    same user can log in again and their unsynced changes are still sent.
 *  - Revoked (logout elsewhere, closed by an admin, password/role change, user
 *    deactivated): delete everything on this device, since that is why it was closed.
 */
export async function endSession({ revoked }) {
  if (revoked) {
    await Promise.all([clearAuth(), authConfig().onReset()]);
    return;
  }
  const session = await readSession();
  if (session) await writeSession({ ...session, token: null });
}

/**
 * Revokes the session on the server (so a copied token stops working) and
 * deletes the session and all local data. Offline, only the local part is done;
 * the server session becomes unusable anyway because the device key is deleted.
 */
export async function logout() {
  if (navigator.onLine) {
    try {
      await api(`${authConfig().authPath}/logout`, { method: 'POST' });
    } catch {
      // Still log out locally; an admin can revoke the session from the Users screen.
    }
  }
  await Promise.all([clearAuth(), authConfig().onReset()]);
}
