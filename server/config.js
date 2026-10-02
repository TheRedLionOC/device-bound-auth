/**
 * Settings of the auth module, set once at startup with configureAuth().
 * Only `database` is required; everything else has a default, so a project only
 * passes what differs. Groups (sessions, signatures, passwords, users) are merged,
 * so passing { sessions: { ttlDays: 7 } } keeps the other session settings.
 */
const DAY_MS = 24 * 60 * 60 * 1000;
const MINUTE_MS = 60 * 1000;

const config = {
  // (env) => database adapter with the users and sessions tables (see adapters/ and
  // schema/ at the package root), e.g. (env) => d1Adapter(env.DB). Required.
  database: null,
  // (env) => secret used to sign tokens. Long and random; changing it logs everyone out.
  jwtSecret: (env) => env.JWT_SECRET,
  // async ({ request, env, username }) => void. Throw to refuse a login attempt
  // (see rate-limits/). null: no limit.
  loginRateLimit: null,

  // Roles a user can have. The first one is the default for new users.
  roles: ['admin', 'user'],
  // Access levels used by routes ({ auth: 'admin' }) → roles allowed. The module itself
  // uses 'any' (every logged-in user) and 'admin' (user management).
  access: { any: ['admin', 'user'], admin: ['admin'] },

  sessions: {
    // A session (and its token) lasts this long since the last refresh. The browser
    // module refreshes at most once per `refreshAfterMs` while in use (default 1 day).
    ttlDays: 30,
    // Expired and revoked sessions are deleted after this long (kept for auditing).
    retentionDays: 365,
    // last_seen_at is written at most this often on reads; writes always update it.
    lastSeenResolutionMs: 5 * MINUTE_MS,
  },
  // Device binding with DPoP proofs (RFC 9449, see dpop.js).
  signatures: {
    // Proofs are accepted this close to the server time (replay window). The browser module
    // corrects its clock with X-Server-Time and retries once on clock_skew, so this only has
    // to cover network delay; raise it for clients without that correction.
    maxClockSkewMs: MINUTE_MS,
    // Require the bh/qh extension claims (hashes of body and query), so a captured proof
    // cannot be reused with other data. false: also accept plain DPoP proofs from other
    // clients (bh/qh are still checked when present); consider useJti then.
    requireBodyAndQueryHashes: true,
    // async ({ jti, expiresAt, env }) => boolean: true the first time a proof id is seen
    // (record it until expiresAt), false for a repeat, which is refused. null: no check.
    useJti: null,
    // Public origin of the API (e.g. 'https://api.example.com') when the server sees another
    // one, e.g. behind a proxy. null: the request's own origin. Compared with htu.
    origin: null,
  },
  passwords: {
    minLength: 8,
    // PBKDF2-SHA256 iterations for new hashes. 100,000 is the maximum Cloudflare Workers
    // supports; other runtimes can go higher (OWASP: 600,000). Existing hashes keep
    // working: each hash stores the iterations it was made with.
    iterations: 100_000,
  },
  // Self sign-up: POST {authPath}/register lets anyone create an account. Off by default.
  signup: {
    enabled: false,
    // Role of self-registered users. Required when enabled; must not have 'admin' access.
    role: null,
    // true: new accounts start inactive and get no session until an admin activates them.
    requireApproval: false,
    // async ({ request, env, body }) => void. Throw an AuthError to refuse, e.g. after
    // checking a CAPTCHA token (Cloudflare Turnstile) sent in the body. null: no check.
    verify: null,
  },
  users: {
    usernameMaxLength: 50,
    nameMaxLength: 100,
    // New username of a deleted user, so the old one can be reused. The column must
    // fit usernameMaxLength + this suffix.
    deletedUsername: (username, { id, now }) =>
      `${username} (deleted ${new Date(now).toISOString().slice(0, 10)} #${id.slice(0, 4)})`,
  },

  // Project hooks. All optional.
  hooks: {
    // Extra fields for the logged-in user (e.g. a stock location). Returns an object
    // merged into `user` on every request and in the login response.
    loadUserContext: async (_env, _user) => ({}),
    // Validates a user create/update before saving; throw to refuse.
    // `previous` is null when creating.
    validateUserChange: async (_env, { data: _data, previous: _previous }) => {},
    // Extra statements ({ sql, params }, see statement()) run in the same batch as a
    // user create/update.
    userStatements: async (_env, { user: _user, previous: _previous, now: _now }) => [],
    // Validates a user delete; throw to refuse.
    validateUserDelete: async (_env, _user) => {},
    // Extra statements ({ sql, params }) run in the same batch as a user delete.
    userDeleteStatements: async (_env, { user: _user, deletedBy: _deletedBy, now: _now }) => [],
  },
};

const GROUPS = ['sessions', 'signatures', 'passwords', 'signup', 'users', 'hooks'];

/** Applies the options all at once: if any is invalid, nothing changes. */
export function configureAuth(options = {}) {
  const next = { ...config };
  for (const [key, value] of Object.entries(options)) {
    if (!(key in config)) throw new Error(`Unknown auth option "${key}"`);
    if (value === undefined) continue;
    next[key] = GROUPS.includes(key) ? { ...config[key], ...value } : value;
  }
  checkSignup(next);
  Object.assign(config, next);
}

/** Refuses a sign-up configuration that would hand out unintended (or admin) access. */
function checkSignup({ signup, roles, access }) {
  if (!signup.enabled) return;
  if (!signup.role) throw new Error('signup.role is required when signup.enabled is true');
  if (!roles.includes(signup.role)) throw new Error(`signup.role "${signup.role}" is not one of roles`);
  if (access.admin?.includes(signup.role)) {
    throw new Error(`signup.role "${signup.role}" must not have admin access`);
  }
}

export function authConfig() {
  return config;
}

/** Whether the user's role is allowed at the given access level. */
export function hasAccess(user, level) {
  return config.access[level]?.includes(user.role) ?? false;
}

/** The database holding users and sessions (an adapter, see store.js). */
export function database(env) {
  if (!config.database) throw new Error('configureAuth({ database }) is required');
  return config.database(env);
}

export function jwtSecret(env) {
  const secret = config.jwtSecret(env);
  if (!secret) throw new Error('The JWT secret is not configured (configureAuth({ jwtSecret }))');
  return secret;
}

export const sessionTtlMs = () => config.sessions.ttlDays * DAY_MS;
export const sessionRetentionMs = () => config.sessions.retentionDays * DAY_MS;
