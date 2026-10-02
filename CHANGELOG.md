# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org): a major version for breaking changes, a minor
version for new options or features, a patch version for fixes.

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
