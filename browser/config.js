/**
 * Settings of the browser auth module, set once at startup with configureAuth()
 * before anything else uses the module. Only `apiUrl` is required.
 */
const config = {
  // Base URL of the API, e.g. https://api.example.com. Required.
  apiUrl: '',
  // Where the server registered registerAuthRoutes() (its `prefix`).
  authPath: '/auth',
  // Renew the token at most this often while the app is in use. Each renewal extends the
  // session by the server's sessions.ttlDays, so keep it well below that.
  refreshAfterMs: 24 * 60 * 60 * 1000,
  // IndexedDB database holding the session and the device key. IndexedDB is isolated
  // per domain, so the same name is safe in every project.
  storageName: 'app-auth',
  // Message of the ApiError thrown when the server cannot be reached (status 0).
  offlineMessage: 'Cannot reach the server',
  // Deletes the project's local data. Called on logout, on a revoked session, and when
  // someone logs in whose data must not be mixed with the previous user's (sameScope).
  onReset: async () => {},
  // (previousUser, newUser) => whether local data can be kept for the new login.
  sameScope: (previous, next) => previous.id === next.id && previous.role === next.role,
};

export function configureAuth(options = {}) {
  for (const [key, value] of Object.entries(options)) {
    if (!(key in config)) throw new Error(`Unknown auth option "${key}"`);
    if (value !== undefined) config[key] = value;
  }
  config.apiUrl = config.apiUrl.replace(/\/+$/, '');
}

export function authConfig() {
  return config;
}
