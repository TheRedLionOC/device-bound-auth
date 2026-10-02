/**
 * device-bound-auth, browser side (`device-bound-auth/browser`): login, device-bound signed API
 * calls, token refresh, expiry and logout. Projects import only from this file.
 *
 * No dependencies (Web Crypto + native IndexedDB): plain ES modules, so the folder can
 * be served as-is without a bundler. Pairs with `device-bound-auth/server`.
 *
 * Usage (all options in config.js, guide in README.md at the package root):
 *   configureAuth({ apiUrl, onReset, sameScope });
 *   await login(username, password);  const data = await api('/path');
 *   window.addEventListener('auth:expired', ({ detail }) => endSession({ revoked: detail.code === 'session_revoked' }));
 *
 * Events on window:
 *   auth:expired  the session ended (detail.code: session_expired | session_revoked; for a
 *                 device that lost its key: session_expired, detail.reason device_key_missing)
 *   auth:outdated a newer version of the app (another tab) upgraded the auth database;
 *                 this tab must reload
 */
export { ApiError, api } from './api.js';
export { configureAuth } from './config.js';
export { changePassword, endSession, getSession, login, logout, refreshTokenIfNeeded } from './session.js';
