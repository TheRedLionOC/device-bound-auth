/**
 * Test server: the server module behind its own router (createAuthRouter), on Bun.serve (Bun) or node:http
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
import { createAuthRouter } from '../server/auth-router.js';
import { hashPassword, statement } from '../server/index.js';
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

/**
 * The module's own router (createAuthRouter), with its /auth and /users routes. Tests add
 * routes to it. The client IP comes from the X-Test-IP header.
 */
export const unexpectedErrors = []; // what onError received (errors that became a 500)
export const router = createAuthRouter({
  cors: { origins: ['https://allowed.example'] },
  onError: (err) => unexpectedErrors.push(err),
});

const handle = (request) => router.fetch(request, { CLIENT_IP: request.headers.get('X-Test-IP') ?? '127.0.0.1' });

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
