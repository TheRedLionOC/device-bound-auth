# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org): a major version for breaking changes, a minor
version for new options or features, a patch version for fixes.

## 2.1.0 — 2026-10-02

- `signatures.maxClockSkewMs` defaults to 60 s (was 5 min). The browser module corrects its
  clock with `X-Server-Time` and retries once on `clock_skew`, so the window only has to
  cover network delay; a shorter window shortens how long a captured proof can be replayed.
  Raise it for clients without clock correction.
- README: the Workers KV example for `useJti` uses `expirationTtl` (KV's minimum is 60 s).

## 2.0.0 — 2026-10-02

**Breaking:** device binding is now standard DPoP and the 1.x format is gone. Every user logs
in again once after upgrading. Update the server and the browser module together.

- Requests use DPoP (RFC 9449): `Authorization: DPoP <token>` plus a `DPoP` proof
  (`typ: dpop+jwt`, ES256, `jti`/`htm`/`htu`/`iat`/`ath`), verified as RFC 9449 §4.3 says.
  Tokens carry `cnf.jkt`.
- Login and sign-up take the device key from a DPoP proof, which also proves the device
  holds the private key. `public_key` in the body is no longer accepted.
- Extension claims `bh` / `qh` (hashes of body and query) keep the protection against
  reusing a captured proof with other data; `signatures.requireBodyAndQueryHashes: false`
  also accepts plain DPoP clients.
- New options: `signatures.useJti` (refuse replayed proofs), `signatures.origin` (public
  origin behind a proxy).
- Removed: the `Bearer` + `X-Device-Timestamp` / `X-Device-Signature` format, and
  `AUTH_REQUEST_HEADERS` now lists `DPoP` instead of the `X-Device-*` headers.
- 401 codes follow authenticity: an authentic token that is not sent with the DPoP scheme or
  not bound to a key gets `session_expired` (keep local data, log in again); a token that is
  not authentic gets `session_revoked` whatever the scheme. So 1.x clients and tokens are
  told to log in again, and a browser whose stored key is incomplete (as 1.x keys are) ends
  its session the same way (`auth:expired`, `reason: 'device_key_missing'`).
- Tests check the RFC shape with jose and interoperability with panva/dpop.

## 1.3.0 — 2026-10-01

- Node support. Database adapters for `node:sqlite`, `pg` and `mysql2` (the project installs
  its own driver; the library still depends only on `jose`), and `nodeHandler` to run the
  fetch-style handlers on `node:http` or Express. It refuses a body already consumed by a
  parser (signed requests need the exact bytes).
- The test suite runs on Bun and Node (`npm test`, `npm run test:node`); GitHub Actions runs
  both runtimes against SQLite, PostgreSQL and MySQL.

## 1.2.0 — 2026-10-01

- Optional self sign-up (`signup` options, off by default): `POST /auth/register` and
  browser `register()`. Fixed non-admin role (checked at startup), optional admin approval,
  `verify` hook for CAPTCHAs, counted against the login rate limit.
- `configureAuth()` is atomic: invalid options leave the previous configuration in place.

## 1.1.0 — 2026-10-01

- New route `POST /auth/password` and browser `changePassword(current, new)`: users change
  their own password (current one required, other sessions closed, rate limited).
- Browser: a session whose device key is missing ends cleanly (`auth:expired` with
  `session_expired` and `reason: 'device_key_missing'`) instead of sending unsigned requests.
- Browser: `api(path, { auth: false })` sends a request without credentials; `login` uses it.
- Password policy errors carry `details.code: 'weak_password'`.
- Tests run on GitHub Actions against SQLite, PostgreSQL and MySQL; Dependabot keeps `jose`
  and the actions up to date.

## 1.0.0 — 2026-10-01

First release, extracted from the wISP ZAMS inventory app.

- Username/password login (PBKDF2-SHA256; each hash stores its iteration count).
- Device-bound sessions: non-extractable ECDSA P-256 key per login, every request signed.
- Session table with immediate revocation, sliding expiration and `session_expired` /
  `session_revoked` 401 codes.
- User administration routes (list, create, update, soft delete, sessions).
- Database adapters: Cloudflare D1 and Bun.SQL (SQLite, PostgreSQL, MySQL), with
  portable SQL and reference tables in `schema/`.
- Login rate limits: Cloudflare Workers binding or in-memory.
- Browser module with no dependencies (Web Crypto + native IndexedDB).
- Every project-specific setting is a `configureAuth()` option.
