# device-bound-auth

Username/password login with **device-bound sessions**, for an API plus a browser app.
Runs on Cloudflare Workers (D1) or Bun (SQLite, PostgreSQL, MySQL).

| Side | Import | Dependencies |
| --- | --- | --- |
| Server | `device-bound-auth/server` + one adapter (+ optional rate limit) | [`jose`](https://github.com/panva/jose) |
| Browser | `device-bound-auth/browser` | none (Web Crypto + IndexedDB, plain ES modules) |

Everything project-specific is an option of `configureAuth()`; only the database
(server) and the API URL (browser) are required.

## Install

```sh
npm install github:TheRedLionOC/device-bound-auth#v1.0.0
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
- **Device binding:** at login the browser creates a non-extractable ECDSA P-256 key and
  sends its public key. Every request is signed (method, path, timestamp, body hash), so a
  copied token is useless on another device, and a copied request expires within
  `signatures.maxClockSkewMs`.
- **401 codes** tell the app what to do: `session_expired` (timed out: keep local data,
  log in again) or `session_revoked` (closed on purpose: delete local data).
- **User administration** (role `admin`): list, create, update, soft delete, list and
  revoke sessions. Deleted users keep their row (history) and free their username.
- **Login rate limiting** (optional, pluggable) and constant-time login responses, so
  timing does not reveal which usernames exist.

## Quick start

### Server: Cloudflare Worker + D1

```js
import { d1Adapter } from 'device-bound-auth/server/adapters/d1';
import { cloudflareRateLimit } from 'device-bound-auth/server/rate-limits/cloudflare';
import {
  AuthError, authResponseHeaders, authenticate, configureAuth, hasAccess,
  registerAuthRoutes, registerUserRoutes,
} from 'device-bound-auth/server';

configureAuth({
  database: (env) => d1Adapter(env.DB),
  loginRateLimit: cloudflareRateLimit(), // optional; bindings in wrangler.jsonc
});

registerAuthRoutes(router);   // /auth/login, /auth/me, /auth/refresh, /auth/logout
registerUserRoutes(router);   // /users... (admin)
```

- Tables: `schema/sqlite.sql` as a D1 migration (copy it into your `migrations/`).
- Secret: `npx wrangler secret put JWT_SECRET` (a long random string).
- Rate limit bindings (`wrangler.jsonc`), each optional:
  `"ratelimits": [{ "name": "LOGIN_LIMIT_PER_USER", "namespace_id": "1001", "simple": { "limit": 5, "period": 60 } }, { "name": "LOGIN_LIMIT_PER_IP", "namespace_id": "1002", "simple": { "limit": 20, "period": 60 } }]`

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

## What the project's server must provide

1. **A router** with `get/post/put/delete(path, handler, { auth })`. `auth` is `'public'`
   or an access level (default `'any'`). Handlers receive
   `{ request, env, params, user, session }` and return a `Response`.
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
| `database` | — (required) | `(env) => adapter`: `d1Adapter(env.DB)` or `bunSqlAdapter(sql)` |
| `jwtSecret` | `(env) => env.JWT_SECRET` | Changing the secret logs everyone out |
| `loginRateLimit` | `null` (no limit) | `cloudflareRateLimit()`, `memoryRateLimit()` or your own `async ({ request, env, username }) => {}` that throws |
| `roles` | `['admin', 'user']` | First one is the default for new users |
| `access` | `{ any: [...roles], admin: ['admin'] }` | Access levels for routes. The module uses `any` and `admin` |
| `sessions.ttlDays` | `30` | Session and token lifetime since the last refresh |
| `sessions.retentionDays` | `365` | Expired/revoked sessions are deleted after this |
| `sessions.lastSeenResolutionMs` | 5 min | `last_seen_at` write frequency on reads |
| `signatures.maxClockSkewMs` | 5 min | Replay window for signed requests |
| `passwords.minLength` | `8` | |
| `passwords.iterations` | `100000` | Maximum on Cloudflare Workers; OWASP recommends 600,000 elsewhere |
| `users.usernameMaxLength` / `nameMaxLength` | `50` / `100` | |
| `users.deletedUsername` | `"name (deleted 2026-01-31 #abcd)"` | New username of a deleted user |
| `hooks.*` | no-ops | Project side effects, see below |

Groups are merged: `{ sessions: { ttlDays: 7 } }` keeps the other session settings.

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

## Browser options: `configureAuth()`

| Option | Default | |
| --- | --- | --- |
| `apiUrl` | — (required) | Base URL of the API |
| `authPath` | `'/auth'` | Server's `registerAuthRoutes` prefix |
| `refreshAfterMs` | 1 day | Token renewal frequency while in use; keep below `sessions.ttlDays` |
| `storageName` | `'app-auth'` | IndexedDB database for the session and device key |
| `offlineMessage` | `'Cannot reach the server'` | Message of `ApiError` with status 0 |
| `onReset` | no-op | Deletes the project's local data (logout, revoked session, different user) |
| `sameScope` | same user id and role | `(previousUser, newUser) =>` whether local data can be kept on login |

Exports: `api(path, { method, body })` (signed call, throws `ApiError` with `status` and
`details`), `login`, `logout`, `getSession`, `refreshTokenIfNeeded`, `endSession({ revoked })`.
Events on `window`: `auth:expired` (`detail.code`) and `auth:outdated` (another tab
upgraded the auth database: reload).

## API

| Method | Path | |
| --- | --- | --- |
| POST | `/auth/login` | `{ username, password, public_key }` → `{ token, user }` (the browser module sends the key) |
| GET | `/auth/me` | Current user |
| POST | `/auth/refresh` | New token, extends the session |
| POST | `/auth/logout` | Revokes the current session |
| GET/POST | `/users` | List / create (admin) |
| PUT/DELETE | `/users/:id` | Update / soft delete (admin) |
| GET | `/users/:id/sessions` | Open sessions of a user (admin) |
| POST | `/users/:id/sessions/revoke` | Close all of them (admin) |
| POST | `/users/:id/sessions/:sessionId/revoke` | Close one (admin) |

## Creating the first admin

There is no sign-up: an admin creates users. Insert the first one directly, hashing the
password with the same function the server uses:

```js
import { hashPassword } from 'device-bound-auth/server';
const { hash, salt } = await hashPassword('a-strong-password');
// INSERT INTO users (id, username, name, password_hash, password_salt, role, active, created_at, updated_at)
// VALUES (<uuid>, 'admin', 'Administrator', <hash>, <salt>, 'admin', 1, <now ms>, <now ms>)
```

## Tests

```sh
npm install                                # bun runs the tests
bun test                                   # SQLite in memory
DATABASE_URL=postgres://... bun test       # or mysql://...?ssl=require (empty test database:
                                           # its users and sessions tables are recreated)
```

The suite runs the server module on Bun with the browser module's signing code and checks
login, signed requests, device binding, replay window, revocation, user administration
and rate limiting.

## Tested with

Cloudflare Workers + D1, and Bun with SQLite, PostgreSQL 18 and MySQL 8.0. The browser
module with Chrome, Firefox and Brave.

## License

MIT
