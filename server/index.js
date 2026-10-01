/**
 * device-bound-auth, server side (`device-bound-auth/server`): users, passwords, device-bound
 * sessions, login rate limiting and user administration. Pairs with `device-bound-auth/browser`.
 * Projects import from this file, plus the adapter and rate limit they choose.
 * Guide: README.md at the package root.
 *
 * Its only dependency is `jose`.
 *   Core (any JavaScript runtime with Web Crypto): the files in this folder
 *   adapters/      database adapters, pick one: d1.js (Cloudflare D1), bun-sql.js (Bun.SQL:
 *                  sqlite://, postgres://, mysql://)
 *   rate-limits/   optional login limits: cloudflare.js (Workers binding), memory.js
 *                  (single long-running server)
 *   ../schema/     users and sessions tables for SQLite/D1, PostgreSQL and MySQL
 */
export { authenticate } from './authenticate.js';
export { configureAuth, hasAccess } from './config.js';
export { AuthError } from './errors.js';
export { AUTH_EXPOSED_HEADERS, AUTH_REQUEST_HEADERS, authResponseHeaders } from './headers.js';
export { hashPassword } from './password.js';
export { registerAuthRoutes } from './routes.js';
export { statement } from './store.js';
export { registerUserRoutes } from './users.js';
