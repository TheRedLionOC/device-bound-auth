/**
 * Test server: the server module on Bun.serve with Bun.SQL, a minimal router, and a
 * client that signs requests with the browser module's own signing code.
 *
 * DATABASE_URL picks the database (default: SQLite in memory). For PostgreSQL/MySQL use an
 * empty test database: its users and sessions tables are dropped and recreated.
 */
import { SQL } from 'bun';
import { readFileSync } from 'node:fs';
import { createDeviceKey, signRequest } from '../browser/device-key.js';
import { bunSqlAdapter } from '../server/adapters/bun-sql.js';
import {
  AuthError,
  authResponseHeaders,
  authenticate,
  hasAccess,
  hashPassword,
  registerAuthRoutes,
  registerUserRoutes,
} from '../server/index.js';

export const DATABASE_URL = process.env.DATABASE_URL ?? 'sqlite://:memory:';

/** Opens the database and creates the module's tables from schema/. */
export async function createDatabase() {
  const sql = new SQL(DATABASE_URL);
  const dialect = sql.options?.adapter ?? 'sqlite';
  const file = { sqlite: 'sqlite', postgres: 'postgres', mysql: 'mysql' }[dialect];
  const schema =
    'DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS users;' +
    readFileSync(new URL(`../schema/${file}.sql`, import.meta.url), 'utf8');
  for (const part of schema.replace(/^--.*$/gm, '').split(';')) {
    if (part.trim()) await sql.unsafe(part);
  }
  return { sql, db: bunSqlAdapter(sql), dialect };
}

/** Inserts a user directly (like a project's create-admin script). */
export async function insertUser(db, { username, password, role = 'admin', iterations }) {
  const { hash, salt } = await hashPassword(password, iterations);
  const id = crypto.randomUUID();
  const { statement } = await import('../server/index.js');
  await db.run(
    statement(
      `INSERT INTO users (id, username, name, password_hash, password_salt, role, active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
      id,
      username,
      username,
      hash,
      salt,
      role,
      Date.now(),
      Date.now(),
    ),
  );
  return id;
}

/** Minimal router with the interface the module expects. */
class Router {
  routes = [];
  add(method, path, handler, { auth = 'any' } = {}) {
    this.routes.push({ method, parts: path.split('/').filter(Boolean), handler, auth });
  }
  get(path, handler, options) {
    this.add('GET', path, handler, options);
  }
  post(path, handler, options) {
    this.add('POST', path, handler, options);
  }
  put(path, handler, options) {
    this.add('PUT', path, handler, options);
  }
  delete(path, handler, options) {
    this.add('DELETE', path, handler, options);
  }
  match(method, pathname) {
    const parts = pathname.split('/').filter(Boolean);
    for (const route of this.routes) {
      if (route.method !== method || route.parts.length !== parts.length) continue;
      const params = {};
      if (route.parts.every((p, i) => (p.startsWith(':') ? ((params[p.slice(1)] = parts[i]), true) : p === parts[i]))) {
        return { route, params };
      }
    }
    return {};
  }
}

/** Starts the server; the client IP comes from the X-Test-IP header (for rate limits). */
export function startServer() {
  const router = new Router();
  registerAuthRoutes(router);
  registerUserRoutes(router);

  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      const env = { CLIENT_IP: request.headers.get('X-Test-IP') ?? '127.0.0.1' };
      let response;
      try {
        const url = new URL(request.url);
        const { route, params } = router.match(request.method, url.pathname);
        if (!route) {
          response = Response.json({ error: 'Not found' }, { status: 404 });
        } else {
          const context = { request, env, url, params, user: null, session: null };
          if (route.auth !== 'public') {
            Object.assign(context, await authenticate(request, env));
            if (!hasAccess(context.user, route.auth)) throw new AuthError(403, 'Forbidden');
          }
          response = await route.handler(context);
        }
      } catch (err) {
        if (!(err instanceof AuthError)) throw err;
        response = Response.json({ error: err.message, details: err.details }, { status: err.status });
      }
      for (const [key, value] of Object.entries(authResponseHeaders())) response.headers.set(key, value);
      return response;
    },
  });
  return { url: `http://localhost:${server.port}`, stop: () => server.stop(true) };
}

let ipCounter = 0;
/** A fresh client IP, so tests do not share rate limit counters. */
export const newIp = () => `10.0.${Math.floor(++ipCounter / 250)}.${ipCounter % 250}`;

/** HTTP client: signs requests like the browser module does. */
export function client(baseUrl) {
  async function call(path, { method = 'GET', body, auth, ip = '127.0.0.1', timestamp, rawBody } = {}) {
    const bodyText = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
    const headers = { 'Content-Type': 'application/json', 'X-Test-IP': ip };
    if (auth) {
      const url = new URL(baseUrl + path);
      headers.Authorization = `Bearer ${auth.token}`;
      const signed = body === undefined && rawBody === undefined ? '' : JSON.stringify(body);
      Object.assign(
        headers,
        await signRequest(auth.key, method, url.pathname + url.search, signed, timestamp ?? Date.now()),
      );
    }
    const response = await fetch(baseUrl + path, { method, headers, body: bodyText });
    return { status: response.status, headers: response.headers, data: await response.json().catch(() => null) };
  }

  async function login(username, password, { ip = newIp() } = {}) {
    const { privateKey, publicJwk } = await createDeviceKey();
    const res = await call('/auth/login', { method: 'POST', ip, body: { username, password, public_key: publicJwk } });
    return { ...res, auth: res.data?.token && { token: res.data.token, key: privateKey } };
  }

  return { call, login };
}
