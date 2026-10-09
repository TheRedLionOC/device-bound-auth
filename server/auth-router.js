/**
 * A router with authentication built in, secure by default (`device-bound-auth/server/auth-router`).
 *
 *   const router = createAuthRouter({ cors: { origins: ['https://app.example.com'] } });
 *   router.get('/items', listItems);                       // needs a session
 *   router.post('/items', saveItem, { auth: 'staff' });    // needs an access level
 *   router.get('/health', health, { auth: 'public' });     // open only when it says so
 *   export default { fetch: router.fetch };                // Workers; Bun.serve({ fetch: router.fetch });
 *                                                          // Node: nodeHandler(router.fetch)
 *
 * For every request it: answers CORS preflights; finds the route (404 / 405); unless the
 * route is 'public', authenticates (401) and checks the access level (403); calls the
 * handler with { request, env, ctx, url, params, user, session }; turns errors into JSON
 * (an error with a numeric `status`, such as AuthError, keeps it; anything else is a 500
 * without details); and adds X-Server-Time and the CORS headers to every response.
 * The /auth and /users routes of this module are registered too (see options).
 *
 * Projects with their own router (Hono, Express...) can keep using authenticate(),
 * hasAccess(), authResponseHeaders() and the header lists instead.
 */
import { authenticate } from './authenticate.js';
import { hasAccess } from './config.js';
import { AuthError } from './errors.js';
import { AUTH_EXPOSED_HEADERS, AUTH_REQUEST_HEADERS, authResponseHeaders } from './headers.js';
import { registerAuthRoutes } from './routes.js';
import { registerUserRoutes } from './users.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * Options:
 *   cors      { origins: string[] | (origin, env) => boolean, headers?: string[],
 *               maxAgeSeconds?: 86400 }. Omit when the browser app is on the same origin.
 *   auth      { prefix: '/auth' } for the login routes, or false to leave them out.
 *   users     { prefix: '/users' } for user administration, or false to leave it out.
 *   onError   (err, context) => void, for errors that become a 500 (default: console.error).
 */
export function createAuthRouter({ cors = null, auth = {}, users = {}, onError = defaultOnError } = {}) {
  const routes = [];

  const add = (method, pattern, handler, { auth: level = 'any' } = {}) => {
    if (typeof handler !== 'function') throw new TypeError(`Handler for ${method} ${pattern} must be a function`);
    routes.push({ method, segments: pattern.split('/').filter(Boolean), handler, level });
    return router;
  };

  const router = {
    get: (pattern, handler, options) => add('GET', pattern, handler, options),
    post: (pattern, handler, options) => add('POST', pattern, handler, options),
    put: (pattern, handler, options) => add('PUT', pattern, handler, options),
    patch: (pattern, handler, options) => add('PATCH', pattern, handler, options),
    delete: (pattern, handler, options) => add('DELETE', pattern, handler, options),

    /** Handles a request: (request, env, ctx) => Response, as Workers, Bun and Deno expect. */
    fetch: async (request, env = {}, ctx = undefined) => {
      const corsHeaders = await corsHeadersFor(cors, request, env);
      let response;
      try {
        response = await handle(routes, request, env, ctx, corsHeaders);
      } catch (err) {
        response = errorResponse(err, { request, env }, onError);
      }
      return withHeaders(response, { ...corsHeaders, ...authResponseHeaders() });
    },
  };

  if (auth) registerAuthRoutes(router, auth);
  if (users) registerUserRoutes(router, users);
  return router;
}

async function handle(routes, request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const method = request.method === 'HEAD' ? 'GET' : request.method;

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  const parts = splitPath(url.pathname);
  const allowed = [];
  let match = null;
  for (const route of routes) {
    const params = matchSegments(route.segments, parts);
    if (!params) continue;
    if (route.method === method) {
      match = { route, params };
      break;
    }
    allowed.push(route.method);
  }
  if (!match) {
    if (allowed.length) {
      return Response.json({ error: 'Method not allowed' }, { status: 405, headers: { Allow: allowed.join(', ') } });
    }
    throw new AuthError(404, 'Not found');
  }

  const context = { request, env, ctx, url, params: match.params, user: null, session: null };
  // Secure by default: only routes that say 'public' skip authentication.
  if (match.route.level !== 'public') {
    Object.assign(context, await authenticate(request, env));
    if (!hasAccess(context.user, match.route.level)) throw new AuthError(403, 'You do not have permission to do this');
  }

  const response = await match.route.handler(context);
  if (!(response instanceof Response)) throw new TypeError(`${method} ${url.pathname} did not return a Response`);
  return request.method === 'HEAD' ? new Response(null, response) : response;
}

/** Path segments, decoded. A segment that is not valid URL encoding is a 400. */
function splitPath(pathname) {
  try {
    return pathname.split('/').filter(Boolean).map(decodeURIComponent);
  } catch {
    throw new AuthError(400, 'Invalid URL');
  }
}

/**
 * Matches "/items/:id" patterns. Parameters never contain "/" or "\" (also encoded as %2F)
 * and are never "." or "..", so a handler that builds a path from one cannot leave its folder.
 */
function matchSegments(segments, parts) {
  if (segments.length !== parts.length) return null;
  const params = {};
  for (let i = 0; i < segments.length; i++) {
    if (segments[i].startsWith(':')) {
      const value = parts[i];
      if (/[/\\]/.test(value) || value === '.' || value === '..') return null;
      params[segments[i].slice(1)] = value;
    } else if (segments[i] !== parts[i]) {
      return null;
    }
  }
  return params;
}

/** JSON for errors: their own status when they carry one, a detail-free 500 otherwise. */
function errorResponse(err, context, onError) {
  const status = Number(err?.status);
  if (err instanceof AuthError || (Number.isInteger(status) && status >= 400 && status < 600)) {
    return Response.json({ error: err.message, details: err.details }, { status });
  }
  onError(err, context);
  return Response.json({ error: 'Internal server error' }, { status: 500 });
}

function defaultOnError(err, { request }) {
  console.error(`${request.method} ${new URL(request.url).pathname} failed:`, err);
}

/** CORS headers for this request's origin, if CORS is configured and the origin is allowed. */
async function corsHeadersFor(cors, request, env) {
  const origin = request.headers.get('Origin');
  if (!cors) return {};
  const vary = { Vary: 'Origin' };
  if (!origin) return vary;
  const allowed =
    typeof cors.origins === 'function' ? await cors.origins(origin, env) : (cors.origins ?? []).includes(origin);
  if (!allowed) return vary;
  return {
    ...vary,
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': [...METHODS, 'OPTIONS'].join(', '),
    'Access-Control-Allow-Headers': [...AUTH_REQUEST_HEADERS, ...(cors.headers ?? [])].join(', '),
    'Access-Control-Expose-Headers': AUTH_EXPOSED_HEADERS.join(', '),
    'Access-Control-Max-Age': String(cors.maxAgeSeconds ?? 86400),
  };
}

/** Responses from fetch() have immutable headers: copy before adding ours. */
function withHeaders(response, headers) {
  const copy = new Response(response.body, response);
  for (const [name, value] of Object.entries(headers)) copy.headers.set(name, value);
  return copy;
}
