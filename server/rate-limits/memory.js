/**
 * Login rate limit kept in memory, for a single long-running server (Bun, Node, Deno):
 *   import { memoryRateLimit } from 'device-bound-auth/server/rate-limits/memory';
 *   configureAuth({ loginRateLimit: memoryRateLimit({ clientIp: ({ request, env }) => ... }) })
 *
 * Counts attempts per username + IP and per IP in a fixed window. Counters live in the
 * process: they reset on restart and are not shared between several instances (use a
 * shared store such as Redis or the database for that). Not suitable for Cloudflare
 * Workers, where each request may run in a different instance (use cloudflare.js).
 *
 * `clientIp({ request, env })` must return the real client IP. Behind a proxy that is
 * usually a header the proxy sets (e.g. X-Forwarded-For); only trust it if the proxy
 * overwrites it. With Bun.serve, put the socket address in the env you pass per request:
 *   fetch(request, server) { const env = { ...baseEnv, CLIENT_IP: server.requestIP(request)?.address }; ... }
 *   memoryRateLimit({ clientIp: ({ env }) => env.CLIENT_IP })
 */
import { AuthError } from '../errors.js';

export function memoryRateLimit({ perUser = 5, perIp = 20, windowMs = 60_000, clientIp }) {
  if (typeof clientIp !== 'function') throw new Error('memoryRateLimit needs a clientIp({ request, env }) function');
  const counters = new Map(); // key → { count, resetAt }

  const hit = (key, limit, now) => {
    let counter = counters.get(key);
    if (!counter || counter.resetAt <= now) {
      counter = { count: 0, resetAt: now + windowMs };
      counters.set(key, counter);
    }
    counter.count += 1;
    return counter.count <= limit;
  };

  return async ({ request, env, username }) => {
    const now = Date.now();
    // Drop expired counters now and then so memory does not grow forever.
    if (counters.size > 10_000) {
      for (const [key, counter] of counters) if (counter.resetAt <= now) counters.delete(key);
    }
    const ip = (await clientIp({ request, env })) ?? 'unknown';
    const userOk = hit(`user:${ip}:${username.trim().toLowerCase()}`, perUser, now);
    const ipOk = hit(`ip:${ip}`, perIp, now);
    if (!userOk || !ipOk) {
      throw new AuthError(429, 'Too many login attempts, try again later', { code: 'rate_limited' });
    }
  };
}
