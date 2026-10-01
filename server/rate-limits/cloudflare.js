/**
 * Login rate limit with the Cloudflare Workers Rate Limiting binding (`ratelimits` in
 * wrangler.jsonc) and the client IP from Cloudflare's CF-Connecting-IP header:
 *   import { cloudflareRateLimit } from 'device-bound-auth/server/rate-limits/cloudflare';
 *   configureAuth({ loginRateLimit: cloudflareRateLimit() })
 *
 * Two limits, each optional (a missing binding skips that check):
 *  - perUser: binding limiting attempts per username from the same IP
 *  - perIp:   binding limiting attempts from one IP across all usernames
 * The number of requests and the period are set on the bindings in wrangler.jsonc.
 */
import { AuthError } from '../errors.js';

export function cloudflareRateLimit({ perUser = 'LOGIN_LIMIT_PER_USER', perIp = 'LOGIN_LIMIT_PER_IP' } = {}) {
  return async ({ request, env, username }) => {
    const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
    const results = await Promise.all([
      env[perUser]?.limit({ key: `${ip}:${username.trim().toLowerCase()}` }),
      env[perIp]?.limit({ key: ip }),
    ]);
    if (results.some((result) => result && !result.success)) {
      throw new AuthError(429, 'Too many login attempts, try again later', { code: 'rate_limited' });
    }
  };
}
