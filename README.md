# device-bound-auth

Username/password login with **device-bound sessions**, for an API plus a browser app.
Runs on Cloudflare Workers (D1), Bun or Node, with SQLite, PostgreSQL or MySQL.

| Side | Import | Dependencies |
| --- | --- | --- |
| Server | `device-bound-auth/server` + one adapter (+ optional rate limit) | [`jose`](https://github.com/panva/jose) |
| Browser | `device-bound-auth/browser` | none (Web Crypto + IndexedDB, plain ES modules) |

Everything project-specific is an option of `configureAuth()`; only the database
(server) and the API URL (browser) are required.

## Install

```sh
npm install github:TheRedLionOC/device-bound-auth#v2.3.0
```

The server side is imported from your Worker or Bun code. The browser side is plain ES
modules with no dependencies: with a bundler, import `device-bound-auth/browser`; without one,
copy `node_modules/device-bound-auth/browser/` (and `LICENSE`) to your static files at build
time and import it from there.

## What it does

- **Passwords:** PBKDF2-SHA256 with a random salt. Each hash stores its iteration count,
  so raising `passwords.iterations` later keeps old passwords working.
- **Sessions:** a row per login in `sessions`, a JWT (HS256) carrying its id. Every request
  re-reads the session and the user, so logout, revoking, deactivating, deleting a user or
  changing their password/role take effect immediately. Sliding expiration: the browser
  refreshes the token while in use.
- **Device binding with DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)): at
  login the browser creates a non-extractable ECDSA P-256 key and proves it holds it; the
  session and its token (`cnf.jkt`) are bound to that key. Every request carries a DPoP proof
  signed by the key, so a copied token is useless on another device and a captured proof
  expires within `signatures.maxClockSkewMs`. See **Device binding (DPoP)** below.
- **401 codes** tell the app what to do with its local data:
  - `session_expired`: the token is authentic but no longer accepted (timed out, or not
    sent with the DPoP scheme / not bound to a key). Keep local data; log in again.
  - `session_revoked`: the session was closed on purpose (logout, admin, password or role
    change, user deactivated) or the token is not authentic. Delete local data.
- **User administration** (role `admin`): list, create, update, soft delete, list and
  revoke sessions. Deleted users keep their row (history) and free their username.
- **Users change their own password** (current one required; other sessions closed).
- **Optional self sign-up**, off by default, with a fixed non-admin role, optional admin
  approval and a hook for CAPTCHAs.
- **Login rate limiting** (optional, pluggable) and constant-time login responses, so
  timing does not reveal which usernames exist.

## Quick start

### Server: Cloudflare Worker + D1

```js
import { configureAuth } from 'device-bound-auth/server';
import { d1Adapter } from 'device-bound-auth/server/adapters/d1';
import { createAuthRouter } from 'device-bound-auth/server/auth-router';
import { cloudflareRateLimit } from 'device-bound-auth/server/rate-limits/cloudflare';

configureAuth({
  database: (env) => d1Adapter(env.DB),
  loginRateLimit: cloudflareRateLimit(), // optional; bindings in wrangler.jsonc
});

// /auth/... and /users/... included. Every route needs a session unless it says 'public'.
const router = createAuthRouter({ cors: { origins: ['https://app.example.com'] } });
router.get('/items', ({ user, env }) => Response.json({ items: [] }));
router.get('/health', () => Response.json({ ok: true }), { auth: 'public' });

export default { fetch: router.fetch };
```

- Tables: `schema/sqlite.sql` as a D1 migration (copy it into your `migrations/`).
- Secret: `npx wrangler secret put JWT_SECRET` (a long random string).
- Rate limit bindings (`wrangler.jsonc`), each optional:
  `"ratelimits": [{ "name": "LOGIN_LIMIT_PER_USER", "namespace_id": "1001", "simple": { "limit": 5, "period": 60 } }, { "name": "LOGIN_LIMIT_PER_IP", "namespace_id": "1002", "simple": { "limit": 20, "period": 60 } }]`
- Local development: if `wrangler.jsonc` has `routes`, `wrangler dev` shows the Worker the
  production URL instead of `http://localhost:8787`, so DPoP proofs (signed for the URL the
  browser called) are refused as made for another URL. Run
  `wrangler dev --local-upstream localhost:8787` (same port) to keep the real one.

### Server: Bun (SQLite, PostgreSQL or MySQL, no driver to install)

```js
import { SQL } from 'bun';
import { configureAuth } from 'device-bound-auth/server';
import { bunSqlAdapter } from 'device-bound-auth/server/adapters/bun-sql';
import { memoryRateLimit } from 'device-bound-auth/server/rate-limits/memory';

const db = bunSqlAdapter(new SQL(process.env.DATABASE_URL)); // once, at startup
configureAuth({
  database: () => db,
  jwtSecret: () => process.env.JWT_SECRET,
  loginRateLimit: memoryRateLimit({ clientIp: ({ env }) => env.CLIENT_IP }),
  passwords: { iterations: 600_000 }, // Bun has no 100,000 cap
});

Bun.serve({
  fetch(request, server) {
    const env = { CLIENT_IP: server.requestIP(request)?.address };
    // ...route with (request, env) as below
  },
});
```

Tables: `schema/sqlite.sql`, `schema/postgres.sql` or `schema/mysql.sql`. MySQL 8 needs
TLS in the URL (`mysql://user:pass@host/db?ssl=require`).

### Server: Node (node:http or Express)

The module works with standard `Request`/`Response`. On Node, `nodeHandler` converts
between those and Node's HTTP server (also Express), and you pick the database adapter for
the driver you use. The library depends on none of them: install only your driver.

| Database | Driver | Adapter |
| --- | --- | --- |
| SQLite | `node:sqlite` (built into Node 22.5+) | `device-bound-auth/server/adapters/node-sqlite` |
| PostgreSQL | `pg` | `device-bound-auth/server/adapters/pg` |
| MySQL | `mysql2` (`mysql2/promise` pool) | `device-bound-auth/server/adapters/mysql2` |

```js
import { createServer } from 'node:http';
import pg from 'pg';
import { configureAuth } from 'device-bound-auth/server';
import { pgAdapter } from 'device-bound-auth/server/adapters/pg';
import { memoryRateLimit } from 'device-bound-auth/server/rate-limits/memory';
import { nodeHandler } from 'device-bound-auth/server/http/node';

const db = pgAdapter(new pg.Pool({ connectionString: process.env.DATABASE_URL })); // once
configureAuth({
  database: () => db,
  jwtSecret: () => process.env.JWT_SECRET,
  loginRateLimit: memoryRateLimit({ clientIp: ({ env }) => env.CLIENT_IP }),
  passwords: { iterations: 600_000 },
});

const router = createAuthRouter(); // import { createAuthRouter } from 'device-bound-auth/server/auth-router'
createServer(nodeHandler((request, req) => router.fetch(request, { CLIENT_IP: req.socket.remoteAddress })))
  .listen(3000);
```

**Express:** mount it on a path, **before** `express.json()` or any body parser:

```js
app.use('/api', nodeHandler((request, req) => router.fetch(request, { CLIENT_IP: req.ip })));
app.use(express.json()); // your other routes
```

DPoP proofs cover the exact body bytes (`bh`); if a parser already read the body,
`nodeHandler` throws an error saying so. Behind a proxy, pass `nodeHandler(fn, { trustProxy:
true })` so `X-Forwarded-Proto` is honored, and take the client IP from your proxy's header.
`node:sqlite` is synchronous, which is normal for SQLite (it runs in-process; the module's
queries take microseconds); use `pg` or `mysql2` for heavy concurrent workloads.

### Browser

```js
import { api, configureAuth, endSession, login, logout } from 'device-bound-auth/browser';
// without a bundler: from '/vendor/device-bound-auth/index.js' (wherever you copied it)

configureAuth({ apiUrl: 'https://api.example.com' });

window.addEventListener('auth:expired', ({ detail }) =>
  endSession({ revoked: detail.code === 'session_revoked' }),
);

await login(username, password);
const { users } = await api('/users');
```

## The router: `createAuthRouter()`

`device-bound-auth/server/auth-router` is a router with authentication built in, **secure by
default**: a route needs a session unless it says `{ auth: 'public' }`, and an access level
that is misspelled or unknown refuses everyone. Use it unless the project has its own router.

```js
const router = createAuthRouter({
  cors: { origins: ['https://app.example.com'] }, // omit when page and API share the origin
  auth: { prefix: '/auth' },                      // or false to leave the login routes out
  users: { prefix: '/users' },                    // or false to leave user administration out
  onError: (err, { request }) => console.error(err), // errors that become a 500
});

router.get('/items/:id', ({ params, user, session, env, url, request, ctx }) => Response.json({}));
router.post('/items', saveItem, { auth: 'staff' }); // an access level from configureAuth({ access })
router.get('/health', health, { auth: 'public' });

router.fetch(request, env, ctx); // Workers: export default { fetch: router.fetch }
                                 // Bun: Bun.serve({ fetch: router.fetch })
                                 // Node: createServer(nodeHandler((request, req) => router.fetch(request, env)))
```

For every request it:

- answers CORS preflights and adds CORS headers only for the configured origins (allowing
  the `DPoP` header and exposing `X-Server-Time`);
- matches the route (404, or 405 with `Allow`); `HEAD` uses the `GET` route;
- unless the route is public, authenticates (401) and checks the access level (403);
- rejects route parameters containing `/`, `\`, `.` or `..` (also URL-encoded), so a handler
  that builds a file path from one cannot leave its folder;
- turns errors into JSON `{ error, details }`: an error with a numeric `status` (such as
  `AuthError`, or the project's own) keeps it; anything else is a 500 without details, and
  the error goes to `onError`;
- adds `X-Server-Time` to every response, errors included.

## Using your own router instead

With Hono, Express or a router of its own, the project wires the pieces itself:

1. **A router** with `get/post/put/delete(path, handler, { auth })`. `auth` is `'public'`
   or an access level (default `'any'`). Handlers receive
   `{ request, env, params, user, session }` and return a `Response`. Register the module's
   routes with `registerAuthRoutes(router, { prefix })` and `registerUserRoutes(router, { prefix })`.
2. **Authentication per route**, before calling the handler:
   ```js
   if (route.auth !== 'public') {
     Object.assign(context, await authenticate(request, env));
     if (!hasAccess(context.user, route.auth)) /* respond 403 */;
   }
   ```
3. **An error handler** that turns `AuthError` into
   `{ error: err.message, details: err.details }` with status `err.status`.
4. **Headers on every response** (errors too): `authResponseHeaders()` (the server time,
   used by browsers to correct their clock). If the browser app is on another origin, CORS
   must allow `AUTH_REQUEST_HEADERS` and expose `AUTH_EXPOSED_HEADERS`.
5. **The tables** from `schema/`, plus any columns or constraints of its own.

## Server options: `configureAuth()`

| Option | Default | |
| --- | --- | --- |
| `database` | — (required) | `(env) => adapter`: `d1Adapter(env.DB)`, `bunSqlAdapter(sql)`, `nodeSqliteAdapter(db)`, `pgAdapter(pool)`, `mysql2Adapter(pool)` or your own (see **Writing your own database adapter**) |
| `jwtSecret` | `(env) => env.JWT_SECRET` | Changing the secret logs everyone out |
| `loginRateLimit` | `null` (no limit) | `cloudflareRateLimit()`, `memoryRateLimit()` or your own `async ({ request, env, username }) => {}` that throws |
| `roles` | `['admin', 'user']` | First one is the default for new users |
| `access` | `{ any: [...roles], admin: ['admin'] }` | Access levels for routes. The module uses `any` and `admin` |
| `sessions.ttlDays` | `30` | Session and token lifetime since the last refresh |
| `sessions.retentionDays` | `365` | Expired/revoked sessions are deleted after this |
| `sessions.lastSeenResolutionMs` | 5 min | `last_seen_at` write frequency on reads |
| `signatures.maxClockSkewMs` | 60 s | Replay window for DPoP proofs (`iat`). The browser module corrects its clock, so this only covers network delay |
| `signatures.requireBodyAndQueryHashes` | `true` | Require the `bh` / `qh` extension claims. `false`: also accept plain DPoP proofs from other clients |
| `signatures.useJti` | `null` | `async ({ jti, expiresAt, env }) => boolean`: `true` the first time a proof id is seen (store it until `expiresAt`); a repeat is refused |
| `signatures.origin` | request origin | Public origin of the API compared with `htu`, when the server sees another one (proxy) |
| `passwords.minLength` | `8` | |
| `passwords.iterations` | `100000` | Maximum on Cloudflare Workers; OWASP recommends 600,000 elsewhere |
| `users.usernameMaxLength` / `nameMaxLength` | `50` / `100` | |
| `users.deletedUsername` | `"name (deleted 2026-01-31 #abcd)"` | New username of a deleted user |
| `signup.enabled` | `false` | Allow self sign-up (`POST /auth/register`); otherwise it answers 404 |
| `signup.role` | — (required when enabled) | Role of new accounts. Must be in `roles` and must not have `admin` access (checked at startup) |
| `signup.requireApproval` | `false` | New accounts start inactive, with no session, until an admin activates them |
| `signup.verify` | `null` | `async ({ request, env, body }) => {}`: throw an `AuthError` to refuse (e.g. check a CAPTCHA token sent in the body) |
| `hooks.*` | no-ops | Project side effects, see below |

Groups are merged: `{ sessions: { ttlDays: 7 } }` keeps the other session settings.
`configureAuth()` applies all options or none: an unknown option or an unsafe sign-up
setting throws and leaves the previous configuration in place.

### Self sign-up

```js
configureAuth({
  signup: {
    enabled: true,
    role: 'member',            // never an admin role
    requireApproval: false,    // true: an admin activates new accounts first
    verify: async ({ env, body }) => { /* e.g. validate body.captcha with Turnstile */ },
  },
});
```

Attempts count against `loginRateLimit`. A taken username answers 409, so sign-up reveals
which usernames exist; that is unavoidable when people choose their own. For public sites,
add a CAPTCHA through `verify`: the rate limit alone does not stop many IPs.

`registerAuthRoutes(router, { prefix: '/auth' })` and
`registerUserRoutes(router, { prefix: '/users' })` take the route prefix.

### Hooks

For projects whose users own other records (e.g. a stock location per user):

| Hook | When |
| --- | --- |
| `loadUserContext(env, user)` | Returns extra fields merged into `user` (every request, login response) |
| `validateUserChange(env, { data, previous })` | Before a create (`previous` null) or update; throw to refuse |
| `userStatements(env, { user, previous, now })` | Returns statements run in the same transaction as the create/update |
| `validateUserDelete(env, user)` | Before a delete; throw to refuse |
| `userDeleteStatements(env, { user, deletedBy, now })` | Returns statements run in the same transaction as the delete |

Statements are plain data, built with `statement(sql, ...params)` exported by the module,
with `?` placeholders and portable SQL, so hooks work with any adapter.

### Writing your own database adapter

The included adapters cover Cloudflare D1, Bun.SQL, `node:sqlite`, `pg` and `mysql2`. For
another driver, write an adapter: an object with four functions. The module never sees
the driver; every query reaches the adapter as plain data, `{ sql, params }`.

| Function | Receives | Must return |
| --- | --- | --- |
| `first(statement)` | `{ sql, params }` | The first row as a plain object, or `null` when there is none (not `undefined`) |
| `all(statement)` | `{ sql, params }` | An array of rows (empty when there are none) |
| `run(statement)` | `{ sql, params }` | Anything; it runs a write |
| `batch(statements)` | An array of `{ sql, params }` | Runs them **in one transaction**: if any fails, none is kept, and the error is thrown |

All four may return promises. Things to get right:

- **`batch` must be atomic.** User changes, the project's hook statements and session
  revocations go together; partial writes would leave them out of step. With a connection
  pool, run the whole batch on one connection taken from the pool (see `adapters/pg.js`).
- **Placeholders are `?`, in order.** If the database numbers them (`$1, $2...` in
  PostgreSQL), convert them; the module's SQL never has a `?` inside a quoted string.
- **Values are strings, numbers or `null`.** Timestamps are milliseconds since epoch. If the
  driver returns `BIGINT` columns as strings, nothing to do: the module converts its own
  timestamp columns.
- **A duplicate username must throw** an error whose message mentions both `unique` or
  `duplicate` and `username` (the drivers' default messages do); the module turns it into a
  409.
- **Create the client once** at startup and share it with the rest of the app, so both use
  the same connections (see `schema/` for the tables).

Example for [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) (synchronous
SQLite for Node):

```js
import Database from 'better-sqlite3';
import { configureAuth } from 'device-bound-auth/server';

export function betterSqliteAdapter(db) {
  const runAll = db.transaction((statements) => {
    for (const { sql, params } of statements) db.prepare(sql).run(...params);
  });
  return {
    first: async ({ sql, params }) => db.prepare(sql).get(...params) ?? null,
    all: async ({ sql, params }) => db.prepare(sql).all(...params),
    run: async ({ sql, params }) => db.prepare(sql).run(...params),
    batch: async (statements) => runAll(statements), // one transaction: all or nothing
  };
}

const db = betterSqliteAdapter(new Database('data/app.db')); // once, at startup
configureAuth({ database: () => db });
```

To check an adapter, make `createDatabase()` in `test/harness.js` return it and run
`npm run test:node`: the suite (login, sessions, user administration, duplicate usernames)
exercises all four functions, including a failing batch.

## Browser options: `configureAuth()`

| Option | Default | |
| --- | --- | --- |
| `apiUrl` | — (required) | Base URL of the API |
| `authPath` | `'/auth'` | Server's `registerAuthRoutes` prefix |
| `refreshAfterMs` | 1 day | Token renewal frequency while in use; keep below `sessions.ttlDays` |
| `storageName` | `'app-auth'` | IndexedDB database for the session and device key |
| `offlineMessage` | `'Cannot reach the server'` | Message of `ApiError` with status 0 |
| `requestTimeoutMs` | `30000` | Give up on a request after this long: `ApiError` status 0, `details.code: 'timeout'` (networks that stay connected but stop answering). `null`: no limit |
| `onReset` | no-op | Deletes the project's local data (logout, revoked session, different user) |
| `sameScope` | same user id and role | `(previousUser, newUser) =>` whether local data can be kept on login |

Exports:

- `api(path, { method, body, auth, signal })`: call with the token and a DPoP proof
  (`auth: false` sends no credentials). Throws `ApiError` with `status` and `details`;
  status 0 when the server cannot be reached or after `requestTimeoutMs`
  (`details.code: 'timeout'`). `signal` (an `AbortSignal`) cancels it, rejecting with the
  signal's reason (`AbortError`).
- `login(username, password)`, `logout()`, `getSession()`, `refreshTokenIfNeeded()`,
  `endSession({ revoked })`.
- `register({ username, name, password, ...extra })`: self sign-up; logs in on this device
  and returns `{ user }`, or `{ pending: true }` when an admin must approve. `extra` fields
  (e.g. `captcha`) reach the server's `signup.verify`.
- `changePassword(currentPassword, newPassword)`: the server checks the current password
  and closes the user's other sessions; this one stays. Fails with 400 and `details.code`
  `wrong_password` or `weak_password`, or 429 (counts against the login rate limit).

Events on `window`:

- `auth:expired`: the session ended; `detail.code` is `session_expired` (keep local data)
  or `session_revoked` (delete it). If the device lost its key (part of the site data was
  cleared), the module ends the session itself as `session_expired` with
  `detail.reason: 'device_key_missing'`, without calling the server.
- `auth:outdated`: another tab upgraded the auth database; reload.

## Device binding (DPoP)

Requests use OAuth 2.0 DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)):

```
Authorization: DPoP <session token>
DPoP: <proof>
```

The proof is a JWT signed with the device key: header `{ typ: 'dpop+jwt', alg: 'ES256', jwk }`,
claims `jti`, `htm`, `htu`, `iat` and `ath` (hash of the token). The server verifies it as
RFC 9449 §4.3 describes and checks that its key is the session's (and the token's `cnf.jkt`).
Login and sign-up send a proof too, so the session is bound to a key the device really holds.

**Extensions.** Standard DPoP covers the method and the URL, not the query or the body. Proofs
also carry `qh` and `bh`, the SHA-256 (base64url) of the query string and of the body, so a
captured proof cannot be reused with other data. The RFC allows extra claims and other
verifiers ignore them. They are required by default; with `requireBodyAndQueryHashes: false`
the server also accepts plain DPoP proofs from other clients and still checks `bh`/`qh` when
present. Tests verify interoperability with [panva/dpop](https://github.com/panva/dpop).

**Replays.** A proof is valid for `maxClockSkewMs`. Within that window an identical request
could be replayed (never a modified one, thanks to `bh`/`qh`). To refuse even that, give
`useJti` a store that remembers proof ids, e.g. Workers KV:

```js
signatures: {
  useJti: async ({ jti, expiresAt, env }) => {
    if (await env.KV.get(`jti:${jti}`)) return false;
    await env.KV.put(`jti:${jti}`, '1', { expirationTtl: 120 }); // KV's minimum is 60 s
    return true;
  },
},
```

This costs a write per request, and KV is eventually consistent, so it narrows replays
rather than ruling them out. A strongly consistent store (Durable Object, Redis, database)
rules them out.

**No server nonces.** `DPoP-Nonce` is not used: freshness comes from `iat` and the browser
corrects its clock with `X-Server-Time`.

**Upgrading from 1.x.** Every user logs in again once: 1.x tokens and clients get 401
`session_expired` (apps keep local data and show the login), and a browser whose stored key
comes from 1.x ends its session itself. Deploy the server and the browser module together:
a 1.x server does not allow the `DPoP` header in CORS, and a 2.0 server refuses 1.x logins.

**Limits.** As with any DPoP in browsers, code running inside the page (XSS, a malicious
extension) can use the key while the page is open, although it cannot copy it. Chrome's
Device Bound Session Credentials keep keys in the TPM, but only for cookies and only in
Chrome.

## API

| Method | Path | |
| --- | --- | --- |
| POST | `/auth/login` | `{ username, password }` + `DPoP` proof → `{ token, user }`, the token bound to the proof's key |
| POST | `/auth/register` | `{ username, name, password }` + `DPoP` proof → `{ token, user }` or `{ pending: true }` (only with `signup.enabled`) |
| GET | `/auth/me` | Current user |
| POST | `/auth/refresh` | New token, extends the session |
| POST | `/auth/logout` | Revokes the current session |
| POST | `/auth/password` | `{ current_password, new_password }`: changes my own password, closes my other sessions |
| GET/POST | `/users` | List / create (admin) |
| PUT/DELETE | `/users/:id` | Update / soft delete (admin) |
| GET | `/users/:id/sessions` | Open sessions of a user (admin) |
| POST | `/users/:id/sessions/revoke` | Close all of them (admin) |
| POST | `/users/:id/sessions/:sessionId/revoke` | Close one (admin) |

## Creating the first admin

Sign-up never creates admins, so insert the first admin directly, hashing the password
with the same function the server uses:

```js
import { hashPassword } from 'device-bound-auth/server';
const { hash, salt } = await hashPassword('a-strong-password');
// INSERT INTO users (id, username, name, password_hash, password_salt, role, active, created_at, updated_at)
// VALUES (<uuid>, 'admin', 'Administrator', <hash>, <salt>, 'admin', 1, <now ms>, <now ms>)
```

## Tests

```sh
npm install
npm test                                   # Bun: Bun.serve + Bun.SQL
npm run test:node                          # Node: node:http + nodeHandler + node:sqlite/pg/mysql2
DATABASE_URL=postgres://... npm test       # or mysql://...?ssl=require (empty test database:
                                           # its users and sessions tables are recreated)
```

The same suite runs on both runtimes with the browser module's signing code and checks
login, signed requests, device binding, replay window, revocation, password changes,
sign-up, user administration and rate limiting. GitHub Actions (`.github/workflows/test.yml`)
runs it on Bun and Node against SQLite, PostgreSQL and MySQL (6 combinations) on every push
and pull request, including Dependabot's weekly updates of `jose`.

## Tested with

Cloudflare Workers + D1; Bun (Bun.SQL) and Node 24 (node:sqlite, pg, mysql2, node:http and
Express) with SQLite, PostgreSQL 18 and MySQL 8.0. The browser module with Chrome, Firefox
and Brave.

## License

MIT
