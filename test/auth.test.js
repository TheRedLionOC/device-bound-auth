import { afterAll, beforeAll, describe, expect, test } from './runner.js';
import * as DPoP from 'dpop';
import * as jose from 'jose';
import { createDeviceKey, createDpopProof } from '../browser/device-key.js';
import { memoryRateLimit } from '../server/rate-limits/memory.js';
import { AuthError, configureAuth, statement } from '../server/index.js';
import { DATABASE_URL, RUNTIME, client, createDatabase, insertUser, newIp, startServer } from './harness.js';

const ADMIN_PASSWORD = 'Admin12345';
const JWT_SECRET = 'test-secret-0123456789abcdef';
let database;
let server;
let api;
let admin; // { token, key }
let adminId;
const unique = () => `u${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

beforeAll(async () => {
  database = await createDatabase();
  configureAuth({
    database: () => database.db,
    jwtSecret: () => JWT_SECRET,
    loginRateLimit: memoryRateLimit({ clientIp: ({ env }) => env.CLIENT_IP }),
    roles: ['user', 'admin'],
    access: { any: ['user', 'admin'], admin: ['admin'] },
    passwords: { iterations: 200_000 },
  });
  // Created with fewer iterations than the configured ones: must keep working.
  adminId = await insertUser(database.db, { username: 'admin', password: ADMIN_PASSWORD, iterations: 100_000 });
  server = await startServer();
  api = client(server.url);
  admin = (await api.login('admin', ADMIN_PASSWORD)).auth;
});

afterAll(async () => {
  await server?.stop();
  await database?.close();
});

console.log(`runtime: ${RUNTIME}, database: ${DATABASE_URL.replace(/:[^:@/]+@/, ':***@')}`);

describe('login', () => {
  test('valid credentials return a token and the user', async () => {
    const res = await api.login('admin', ADMIN_PASSWORD);
    expect(res.status).toBe(200);
    expect(res.data.user).toMatchObject({ username: 'admin', role: 'admin' });
  });

  test('username is case-insensitive', async () => {
    expect((await api.login('ADMIN', ADMIN_PASSWORD)).status).toBe(200);
  });

  test('wrong password and unknown user get the same 401', async () => {
    const wrong = await api.login('admin', 'nope-nope');
    const unknown = await api.login(unique(), 'nope-nope');
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.data.error).toBe(unknown.data.error);
  });

  test('a DPoP proof is required to bind the new session', async () => {
    const res = await api.call('/auth/login', {
      method: 'POST',
      ip: newIp(),
      body: { username: 'admin', password: ADMIN_PASSWORD },
    });
    expect(`${res.status} ${res.data.details.code}`).toBe('401 invalid_dpop_proof');
  });

  test('password hashes without a stored iteration count still verify', async () => {
    const username = unique();
    const id = await insertUser(database.db, { username, password: 'Password1', iterations: 100_000 });
    await database.db.run(
      statement("UPDATE users SET password_salt = SUBSTR(password_salt, 8) WHERE id = ?", id), // drop "100000$"
    );
    expect((await api.login(username, 'Password1')).status).toBe(200);
  });

  test('every response carries X-Server-Time', async () => {
    const res = await api.call('/auth/me');
    expect(Number(res.headers.get('X-Server-Time'))).toBeGreaterThan(0);
  });
});

describe('signed requests (device binding)', () => {
  test('a signed request works', async () => {
    const res = await api.call('/auth/me', { auth: admin });
    expect(res.status).toBe(200);
    expect(res.data.user.username).toBe('admin');
  });

  test('a token without a signature is rejected', async () => {
    const res = await fetch(`${server.url}/auth/me`, { headers: { Authorization: `Bearer ${admin.token}` } });
    expect(res.status).toBe(401);
  });

  test('a token signed by another device is rejected', async () => {
    const { privateKey } = await createDeviceKey();
    const res = await api.call('/auth/me', { auth: { token: admin.token, key: privateKey } });
    expect(res.status).toBe(401);
  });

  test('a body changed after signing is rejected', async () => {
    const res = await api.call('/users', {
      method: 'POST',
      auth: admin,
      body: { username: unique(), name: 'x', password: 'Password1' },
      rawBody: JSON.stringify({ username: unique(), name: 'x', password: 'Password1', role: 'admin' }),
    });
    expect(res.status).toBe(401);
  });

  test('an old signature (replay) is rejected with clock_skew', async () => {
    expect((await api.call('/auth/me', { auth: admin, timestamp: Date.now() - 30 * 1000 })).status).toBe(200);
    const res = await api.call('/auth/me', { auth: admin, timestamp: Date.now() - 2 * 60 * 1000 });
    expect(res.status).toBe(401);
    expect(res.data.details.code).toBe('clock_skew');
  });

  test('a forged token is rejected as revoked', async () => {
    const res = await api.call('/auth/me', { auth: { ...admin, token: `${admin.token}x` } });
    expect(res.status).toBe(401);
    expect(res.data.details.code).toBe('session_revoked');
  });
});

describe('DPoP (RFC 9449)', () => {
  const decode = (jwt) => jwt.split('.').slice(0, 2).map((part) => JSON.parse(Buffer.from(part, 'base64url').toString()));
  const b64sha256 = async (text) =>
    Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))).toString('base64url');
  const proofFor = (auth, method, path, { bodyText = '', accessToken = auth.token, at = Date.now() } = {}) =>
    createDpopProof(
      { privateKey: auth.key, publicJwk: auth.publicJwk },
      { method, url: new URL(server.url + path), accessToken, bodyText, timestamp: at },
    );

  test('proofs and tokens have the RFC shape, checked independently with jose', async () => {
    const { auth } = await api.login('admin', ADMIN_PASSWORD);
    const proof = await proofFor(auth, 'GET', '/users?active=1');
    const [header, payload] = decode(proof);
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(Object.keys(header.jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']); // public part only
    expect(payload.htm).toBe('GET');
    expect(payload.htu).toBe(`${server.url}/users`); // without the query
    expect(typeof payload.jti).toBe('string');
    expect(payload.ath).toBe(await b64sha256(auth.token));
    expect(payload.qh).toBe(await b64sha256('?active=1'));
    const { payload: verified } = await jose.jwtVerify(proof, jose.EmbeddedJWK, { typ: 'dpop+jwt', algorithms: ['ES256'] });
    expect(verified.jti).toBe(payload.jti);

    const [, token] = decode(auth.token);
    expect(token.cnf.jkt).toBe(await jose.calculateJwkThumbprint(auth.publicJwk));
  });

  test('interoperates with an independent DPoP implementation (panva/dpop)', async () => {
    const keypair = await DPoP.generateKeyPair('ES256');
    const body = JSON.stringify({ username: 'admin', password: ADMIN_PASSWORD });
    const loginProof = await DPoP.generateProof(keypair, `${server.url}/auth/login`, 'POST', undefined, undefined, {
      bh: await b64sha256(body),
    });
    const login = await api.call('/auth/login', { method: 'POST', ip: newIp(), rawBody: body, proof: loginProof });
    expect(login.status).toBe(200);
    const token = login.data.token;
    const plain = (method, path) => DPoP.generateProof(keypair, server.url + path, method, undefined, token);
    const headers = { Authorization: `DPoP ${token}` };

    // A plain proof is enough for requests without body or query.
    expect((await api.call('/auth/me', { headers, proof: await plain('GET', '/auth/me') })).status).toBe(200);
    // With a body, the bh extension is required by default...
    const refused = await api.call('/auth/refresh', { method: 'POST', headers, proof: await plain('POST', '/auth/refresh') });
    expect(refused.data.details.code).toBe('invalid_dpop_proof');
    // ...unless the project allows plain DPoP clients.
    configureAuth({ signatures: { requireBodyAndQueryHashes: false } });
    try {
      const ok = await api.call('/auth/refresh', { method: 'POST', headers, proof: await plain('POST', '/auth/refresh') });
      expect(ok.status).toBe(200);
    } finally {
      configureAuth({ signatures: { requireBodyAndQueryHashes: true } });
    }
  });

  test('a proof for another method, URL, query, body or token is refused', async () => {
    const { auth } = await api.login('admin', ADMIN_PASSWORD);
    const refusedWith = async (proof, options = {}) => {
      const res = await api.call(options.path ?? '/users?active=1', { auth, proof, ...options });
      return `${res.status} ${res.data?.details?.code}`;
    };
    const expected = '401 invalid_dpop_proof';
    expect(await refusedWith(await proofFor(auth, 'POST', '/users?active=1'))).toBe(expected); // method
    expect(await refusedWith(await proofFor(auth, 'GET', '/auth/me'))).toBe(expected); // URL
    expect(await refusedWith(await proofFor(auth, 'GET', '/users?active=0'))).toBe(expected); // query
    expect(await refusedWith(await proofFor(auth, 'GET', '/users?active=1', { accessToken: 'another-token' }))).toBe(expected);
    const body = { username: unique(), name: 'x', password: 'Password1' };
    const proof = await proofFor(auth, 'POST', '/users', { bodyText: JSON.stringify(body) });
    const tampered = JSON.stringify({ ...body, role: 'admin' });
    expect(await refusedWith(proof, { path: '/users', method: 'POST', body, rawBody: tampered })).toBe(expected);
  });

  test('forged proofs are refused: alg none, wrong typ, key of another session', async () => {
    const { auth } = await api.login('admin', ADMIN_PASSWORD);
    const valid = await proofFor(auth, 'GET', '/auth/me');
    const [header, payload] = decode(valid);
    const unsigned = [{ ...header, alg: 'none' }, payload].map((part) => Buffer.from(JSON.stringify(part)).toString('base64url'));
    expect((await api.call('/auth/me', { auth, proof: `${unsigned.join('.')}.` })).status).toBe(401);

    const wrongTyp = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk: auth.publicJwk })
      .sign(auth.key);
    expect((await api.call('/auth/me', { auth, proof: wrongTyp })).status).toBe(401);

    const other = (await api.login('admin', ADMIN_PASSWORD)).auth;
    const res = await api.call('/auth/me', { auth, proof: await proofFor({ ...other, token: auth.token }, 'GET', '/auth/me') });
    expect(res.data.details.code).toBe('invalid_dpop_proof');
  });

  test('useJti refuses a replayed proof', async () => {
    const seen = new Set();
    configureAuth({ signatures: { useJti: async ({ jti }) => !seen.has(jti) && Boolean(seen.add(jti)) } });
    try {
      const { auth } = await api.login('admin', ADMIN_PASSWORD);
      const proof = await proofFor(auth, 'GET', '/auth/me');
      expect((await api.call('/auth/me', { auth, proof })).status).toBe(200);
      const replay = await api.call('/auth/me', { auth, proof });
      expect(replay.status).toBe(401);
      expect(replay.data.details.code).toBe('invalid_dpop_proof');
    } finally {
      configureAuth({ signatures: { useJti: null } });
    }
  });

  test('authentic tokens used without DPoP expire; forged tokens are revoked', async () => {
    const { auth } = await api.login('admin', ADMIN_PASSWORD);
    const code = async (token, scheme = 'DPoP') => {
      const res =
        scheme === 'DPoP'
          ? await api.call('/auth/me', { auth: { ...auth, token } })
          : await api.call('/auth/me', { headers: { Authorization: `${scheme} ${token}` } });
      return `${res.status} ${res.data.details.code}`;
    };
    const sign = (claims, secret = JWT_SECRET) =>
      new jose.SignJWT(claims).setProtectedHeader({ alg: 'HS256', typ: 'JWT' }).sign(new TextEncoder().encode(secret));
    const [, claims] = decode(auth.token);

    // Authentic (issued by this server) but not used as required: log in again, keep data.
    expect(await code(auth.token, 'Bearer')).toBe('401 session_expired');
    const { cnf: _cnf, ...unbound } = claims;
    expect(await code(await sign(unbound))).toBe('401 session_expired');

    // Not authentic (another secret): revoked, whatever the scheme.
    const forged = await sign(claims, 'another-secret-0123456789');
    expect(await code(forged)).toBe('401 session_revoked');
    expect(await code(forged, 'Bearer')).toBe('401 session_revoked');

    // Login without a DPoP proof: no key to bind the session to.
    const noProof = await api.login('admin', ADMIN_PASSWORD, { proof: null });
    expect(`${noProof.status} ${noProof.data.details.code}`).toBe('401 invalid_dpop_proof');
  });
});

describe('sessions', () => {
  test('refresh returns a new working token', async () => {
    const { auth } = await api.login('admin', ADMIN_PASSWORD);
    const res = await api.call('/auth/refresh', { method: 'POST', auth });
    expect(res.status).toBe(200);
    expect((await api.call('/auth/me', { auth: { ...auth, token: res.data.token } })).status).toBe(200);
  });

  test('logout revokes the session', async () => {
    const { auth } = await api.login('admin', ADMIN_PASSWORD);
    expect((await api.call('/auth/logout', { method: 'POST', auth })).status).toBe(200);
    const res = await api.call('/auth/me', { auth });
    expect(res.status).toBe(401);
    expect(res.data.details.code).toBe('session_revoked');
  });
});

describe('self sign-up', () => {
  // Like the browser: a DPoP proof binds the new session (`withProof: false` sends none).
  const register = async (body, { ip = newIp(), withProof = true } = {}) => {
    const { privateKey, publicJwk } = await createDeviceKey();
    const proof = withProof
      ? await createDpopProof(
          { privateKey, publicJwk },
          { method: 'POST', url: new URL(`${server.url}/auth/register`), bodyText: JSON.stringify(body), timestamp: Date.now() },
        )
      : undefined;
    const res = await api.call('/auth/register', { method: 'POST', ip, body, proof });
    return { ...res, auth: res.data?.token && { token: res.data.token, key: privateKey, publicJwk } };
  };
  const enable = (signup) => configureAuth({ signup: { enabled: true, role: 'user', requireApproval: false, verify: null, ...signup } });
  afterAll(() => configureAuth({ signup: { enabled: false, requireApproval: false, verify: null } }));

  test('is disabled by default (404)', async () => {
    expect((await register({ username: unique(), name: 'x', password: 'Password1' })).status).toBe(404);
  });

  test('unsafe configurations are refused and change nothing', () => {
    expect(() => configureAuth({ signup: { enabled: true } })).toThrow('signup.role is required');
    expect(() => configureAuth({ signup: { enabled: true, role: 'admin' } })).toThrow('must not have admin access');
    expect(() => configureAuth({ signup: { enabled: true, role: 'boss' } })).toThrow('is not one of roles');
  });

  test('creates the account with the configured role and logs in on this device', async () => {
    enable();
    const username = unique();
    const res = await register({ username, name: 'New person', password: 'Password1', role: 'admin' });
    expect(res.status).toBe(201);
    expect(res.data.user).toMatchObject({ username, role: 'user' }); // a role in the body is ignored
    const me = await api.call('/auth/me', { auth: res.auth });
    expect(me.status).toBe(200);
    expect((await api.call('/users', { auth: res.auth })).status).toBe(403);

    const again = await register({ username, name: 'Again', password: 'Password1' });
    expect(again.status).toBe(409);
    expect(again.data.details.code).toBe('duplicate');
    expect((await register({ username: unique(), name: 'x', password: 'short' })).data.details.code).toBe('weak_password');
    const noProof = await register({ username: unique(), name: 'x', password: 'Password1' }, { withProof: false });
    expect(noProof.data.details.code).toBe('invalid_dpop_proof');
  });

  test('requireApproval: inactive until an admin activates it', async () => {
    enable({ requireApproval: true });
    const username = unique();
    const res = await register({ username, name: 'Pending', password: 'Password1' });
    expect(res.status).toBe(201);
    expect(res.data).toEqual({ pending: true });
    expect((await api.login(username, 'Password1')).status).toBe(401);

    const { data } = await api.call('/users', { auth: admin });
    const user = data.users.find((u) => u.username === username);
    expect(user.active).toBe(0);
    await api.call(`/users/${user.id}`, { method: 'PUT', auth: admin, body: { username, name: 'Pending', role: 'user', active: 1 } });
    expect((await api.login(username, 'Password1')).status).toBe(200);
  });

  test('the verify hook can refuse (e.g. a CAPTCHA)', async () => {
    enable({
      verify: async ({ body }) => {
        if (body.captcha !== 'ok') throw new AuthError(400, 'CAPTCHA failed', { code: 'captcha' });
      },
    });
    const refused = await register({ username: unique(), name: 'Bot', password: 'Password1' });
    expect(refused.status).toBe(400);
    expect(refused.data.details.code).toBe('captcha');
    expect((await register({ username: unique(), name: 'Human', password: 'Password1', captcha: 'ok' })).status).toBe(201);
  });

  test('attempts count against the login rate limit', async () => {
    enable();
    const ip = newIp();
    const username = unique();
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await register({ username, name: 'x', password: 'short' }, { ip })).status);
    expect(statuses[5]).toBe(429);
  });
});

describe('changing my own password', () => {
  const change = (auth, body, ip) => api.call('/auth/password', { method: 'POST', auth, body, ip });

  test('needs the current password, keeps this session, closes the others', async () => {
    const username = unique();
    await api.call('/users', { method: 'POST', auth: admin, body: { username, name: 'User', password: 'Password1' } });
    const here = await api.login(username, 'Password1');
    const elsewhere = await api.login(username, 'Password1');

    let res = await change(here.auth, { current_password: 'wrong-one', new_password: 'Password2' });
    expect(res.status).toBe(400);
    expect(res.data.details.code).toBe('wrong_password');

    res = await change(here.auth, { current_password: 'Password1', new_password: 'short' });
    expect(res.status).toBe(400);
    expect(res.data.details.code).toBe('weak_password');

    res = await change(here.auth, { current_password: 'Password1', new_password: 'Password2' });
    expect(res.status).toBe(200);
    expect((await api.call('/auth/me', { auth: here.auth })).status).toBe(200); // this session stays
    const other = await api.call('/auth/me', { auth: elsewhere.auth });
    expect(other.status).toBe(401);
    expect(other.data.details.code).toBe('session_revoked');

    expect((await api.login(username, 'Password1')).status).toBe(401);
    expect((await api.login(username, 'Password2')).status).toBe(200);
  });

  test('requires a session and the current password field', async () => {
    expect((await api.call('/auth/password', { method: 'POST', body: { current_password: 'x', new_password: 'Password9' } })).status).toBe(401);
    expect((await change(admin, { new_password: 'Password9' })).status).toBe(400);
  });

  test('guessing the current password is rate limited', async () => {
    const username = unique();
    await api.call('/users', { method: 'POST', auth: admin, body: { username, name: 'User', password: 'Password1' } });
    const { auth } = await api.login(username, 'Password1');
    const ip = newIp();
    const statuses = [];
    for (let i = 0; i < 6; i++) {
      statuses.push((await change(auth, { current_password: `guess-${i}`, new_password: 'Password2' }, ip)).status);
    }
    expect(statuses[5]).toBe(429);
  });
});

describe('user administration', () => {
  test('validation errors', async () => {
    const create = (body) => api.call('/users', { method: 'POST', auth: admin, body });
    expect((await create({ username: '', name: 'x', password: 'Password1' })).data.error).toBe(
      'Invalid data: username is required',
    );
    expect((await create({ username: unique(), name: 'x', password: 'Password1', role: 'boss' })).status).toBe(400);
    expect((await create({ username: unique(), name: 'x', password: 'short' })).status).toBe(400);
    expect((await create({ username: unique(), name: 'x', password: 'Password1', active: 'maybe' })).status).toBe(400);
  });

  test('create, duplicate, update, sessions, delete', async () => {
    const username = unique();
    let res = await api.call('/users', {
      method: 'POST',
      auth: admin,
      body: { username: `  ${username} `, name: 'User', password: 'Password1' },
    });
    expect(res.status).toBe(201);
    expect(res.data.user).toMatchObject({ username, role: 'user', active: 1 });
    const id = res.data.user.id;

    res = await api.call('/users', { method: 'POST', auth: admin, body: { username, name: 'Again', password: 'Password1' } });
    expect(res.status).toBe(409);
    expect(res.data.details.code).toBe('duplicate');

    const user = await api.login(username, 'Password1');
    expect(user.status).toBe(200);
    expect((await api.call('/users', { auth: user.auth })).status).toBe(403); // not admin

    res = await api.call(`/users/${id}/sessions`, { auth: admin });
    expect(res.data.sessions).toHaveLength(1);
    expect(typeof res.data.sessions[0].created_at).toBe('number');

    res = await api.call(`/users/${id}`, {
      method: 'PUT',
      auth: admin,
      body: { username, name: 'Renamed', role: 'user', password: 'Password2' },
    });
    expect(res.data.user.name).toBe('Renamed');
    expect((await api.call('/auth/me', { auth: user.auth })).status).toBe(401); // password change closes sessions
    expect((await api.login(username, 'Password2')).status).toBe(200);

    expect((await api.call(`/users/${id}`, { method: 'DELETE', auth: admin })).status).toBe(200);
    expect((await api.login(username, 'Password2')).status).toBe(401);
    res = await api.call('/users', { method: 'POST', auth: admin, body: { username, name: 'Reuse', password: 'Password1' } });
    expect(res.status).toBe(201); // username freed
  });

  test('revoking one session and all sessions', async () => {
    const username = unique();
    const { data } = await api.call('/users', {
      method: 'POST',
      auth: admin,
      body: { username, name: 'User', password: 'Password1' },
    });
    const id = data.user.id;
    const first = await api.login(username, 'Password1');
    const second = await api.login(username, 'Password1');

    const { data: list } = await api.call(`/users/${id}/sessions`, { auth: admin });
    expect(list.sessions).toHaveLength(2);
    expect((await api.call(`/users/${id}/sessions/${list.sessions[0].id}/revoke`, { method: 'POST', auth: admin })).status).toBe(200);
    expect((await api.call(`/users/${id}/sessions/not-a-session/revoke`, { method: 'POST', auth: admin })).status).toBe(404);

    expect((await api.call(`/users/${id}/sessions/revoke`, { method: 'POST', auth: admin })).status).toBe(200);
    expect((await api.call('/auth/me', { auth: first.auth })).status).toBe(401);
    expect((await api.call('/auth/me', { auth: second.auth })).status).toBe(401);
  });

  test('deactivating a user closes their sessions', async () => {
    const username = unique();
    const { data } = await api.call('/users', {
      method: 'POST',
      auth: admin,
      body: { username, name: 'User', password: 'Password1' },
    });
    const user = await api.login(username, 'Password1');
    await api.call(`/users/${data.user.id}`, { method: 'PUT', auth: admin, body: { username, name: 'User', active: 0 } });
    const res = await api.call('/auth/me', { auth: user.auth });
    expect(res.status).toBe(401);
    expect(res.data.details.code).toBe('session_revoked');
    expect((await api.login(username, 'Password1')).status).toBe(401);
  });

  test('an admin cannot remove their own access or delete themselves', async () => {
    const own = await api.call(`/users/${adminId}`, {
      method: 'PUT',
      auth: admin,
      body: { username: 'admin', name: 'admin', role: 'user' },
    });
    expect(own.status).toBe(400);
    expect((await api.call(`/users/${adminId}`, { method: 'DELETE', auth: admin })).status).toBe(400);
  });

  test('deleted usernames fit with the maximum length', async () => {
    const username = unique().padEnd(50, 'x');
    const { data } = await api.call('/users', {
      method: 'POST',
      auth: admin,
      body: { username, name: 'Long', password: 'Password1' },
    });
    expect((await api.call(`/users/${data.user.id}`, { method: 'DELETE', auth: admin })).status).toBe(200);
  });

  test('new hashes store the configured iteration count', async () => {
    const username = unique();
    await api.call('/users', { method: 'POST', auth: admin, body: { username, name: 'x', password: 'Password1' } });
    const row = await database.db.first(statement('SELECT password_salt FROM users WHERE username = ?', username));
    expect(row.password_salt.startsWith('200000$')).toBe(true);
  });
});

describe('rate limiting', () => {
  test('the 6th attempt for a username from one IP is refused', async () => {
    const ip = newIp();
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await api.login('admin', 'wrong-password', { ip })).status);
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses[5]).toBe(429);
  });
});

describe('configuration', () => {
  test('unknown options are rejected', () => {
    expect(() => configureAuth({ sesions: { ttlDays: 1 } })).toThrow('Unknown auth option');
  });
});
