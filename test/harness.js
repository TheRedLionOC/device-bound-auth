/**
 * Test server: the server module behind a minimal router, on Bun.serve (Bun) or node:http
 * through nodeHandler (Node), plus a client that signs requests with the browser module's
 * own signing code.
 *
 * DATABASE_URL picks the database (default: SQLite in memory). For PostgreSQL/MySQL use an
 * empty test database: its users and sessions tables are dropped and recreated.
 *   Bun:  Bun.SQL (bun-sql adapter)
 *   Node: node:sqlite, pg or mysql2 (their adapters)
 */
import { readFileSync } from 'node:fs';
import { createDeviceKey, createDpopProof } from '../browser/device-key.js';
import {
  AuthError,
  authResponseHeaders,
  authenticate,
  hasAccess,
  hashPassword,
  registerAuthRoutes,
  registerUserRoutes,
  statement,
} from '../server/index.js';
import { isBun } from './runner.js';

export const DATABASE_URL = process.env.DATABASE_URL ?? 'sqlite://:memory:';
export const RUNTIME = isBun ? 'bun' : 'node';

const dialectOf = (url) => (url.startsWith('postgres') ? 'postgres' : url.startsWith('mysql') ? 'mysql' : 'sqlite');

function schemaStatements(dialect) {
  const schema =
    'DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS users;' +
    readFileSync(new URL(`../schema/${dialect}.sql`, import.meta.url), 'utf8');
  return schema
    .replace(/^--.*$/gm, '')
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean);
}

/** Opens the database with the adapter for this runtime and creates the module's tables. */
export async function createDatabase() {
  const dialect = dialectOf(DATABASE_URL);
  const statements = schemaStatements(dialect);

  if (isBun) {
    const { SQL } = await import('bun');
    const { bunSqlAdapter } = await import('../server/adapters/bun-sql.js');
    const sql = new SQL(DATABASE_URL);
    for (const part of statements) await sql.unsafe(part);
    return { db: bunSqlAdapter(sql), dialect, close: () => sql.close() };
  }

  if (dialect === 'sqlite') {
    const { DatabaseSync } = await import('node:sqlite');
    const { nodeSqliteAdapter } = await import('../server/adapters/node-sqlite.js');
    const database = new DatabaseSync(DATABASE_URL.replace(/^sqlite:\/\//, ''));
    for (const part of statements) database.exec(part);
    return { db: nodeSqliteAdapter(database), dialect, close: async () => database.close() };
  }

  if (dialect === 'postgres') {
    const { default: pg } = await import('pg');
    const { pgAdapter } = await import('../server/adapters/pg.js');
    const pool = new pg.Pool({ connectionString: DATABASE_URL });
    for (const part of statements) await pool.query(part);
    return { db: pgAdapter(pool), dialect, close: () => pool.end() };
  }

  const mysql = await import('mysql2/promise');
  const { mysql2Adapter } = await import('../server/adapters/mysql2.js');
  const url = new URL(DATABASE_URL);
  const pool = mysql.createPool({
    host: url.hostname,
    port: Number(url.port || 3306),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: url.pathname.slice(1),
    // MySQL 8 uses a self-signed certificate; TLS is needed by its default authentication.
    ssl: url.searchParams.get('ssl') === 'require' ? { rejectUnauthorized: false } : undefined,
  });
  for (const part of statements) await pool.query(part);
  return { db: mysql2Adapter(pool), dialect, close: () => pool.end() };
}

/** Inserts a user directly (like a project's create-admin script). */
export async function insertUser(db, { username, password, role = 'admin', iterations }) {
  const { hash, salt } = await hashPassword(password, iterations);
  const id = crypto.randomUUID();
  const now = Date.now();
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
      now,
      now,
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

const router = new Router();
registerAuthRoutes(router);
registerUserRoutes(router);

/** The fetch-style handler shared by both runtimes. The client IP comes from X-Test-IP. */
async function handle(request) {
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
}

/** Starts the server on a free port: Bun.serve, or node:http through nodeHandler. */
export async function startServer() {
  if (isBun) {
    const server = Bun.serve({ port: 0, fetch: handle });
    return { url: `http://localhost:${server.port}`, stop: async () => server.stop(true) };
  }
  const { createServer } = await import('node:http');
  const { nodeHandler } = await import('../server/http/node.js');
  const server = createServer(nodeHandler(handle));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stop: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  };
}

let ipCounter = 0;
/** A fresh client IP, so tests do not share rate limit counters. */
export const newIp = () => `10.0.${Math.floor(++ipCounter / 250)}.${ipCounter % 250}`;

/**
 * HTTP client: proves requests with DPoP like the browser module does. `auth` is { token,
 * key, publicJwk }. `rawBody` sends other bytes than the signed `body` (tampering tests);
 * `proof` overrides the DPoP header; `headers` adds or overrides headers.
 */
export function client(baseUrl) {
  async function call(path, { method = 'GET', body, auth, ip = '127.0.0.1', timestamp, rawBody, proof, headers: extra } = {}) {
    const signed = body === undefined ? '' : JSON.stringify(body);
    const bodyText = rawBody ?? (body === undefined ? undefined : signed);
    const headers = { 'Content-Type': 'application/json', 'X-Test-IP': ip, ...extra };
    const url = new URL(baseUrl + path);
    const at = timestamp ?? Date.now();
    if (auth) {
      headers.Authorization = `DPoP ${auth.token}`;
      headers.DPoP =
        proof ??
        (await createDpopProof(
          { privateKey: auth.key, publicJwk: auth.publicJwk },
          { method, url, accessToken: auth.token, bodyText: signed, timestamp: at },
        ));
    } else if (proof) {
      headers.DPoP = proof;
    }
    const response = await fetch(url, { method, headers, body: bodyText });
    return { status: response.status, headers: response.headers, data: await response.json().catch(() => null) };
  }

  /** Logs in with a new device key, bound with a DPoP proof (`proof: null` sends none). */
  async function login(username, password, { ip = newIp(), proof } = {}) {
    const { privateKey, publicJwk } = await createDeviceKey();
    const url = new URL(`${baseUrl}/auth/login`);
    const body = { username, password };
    const sent =
      proof === null
        ? undefined
        : await createDpopProof({ privateKey, publicJwk }, { method: 'POST', url, bodyText: JSON.stringify(body), timestamp: Date.now() });
    const res = await call('/auth/login', { method: 'POST', ip, body, proof: sent });
    return { ...res, auth: res.data?.token && { token: res.data.token, key: privateKey, publicJwk } };
  }

  return { call, login };
}
