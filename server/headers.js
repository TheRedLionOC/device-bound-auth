/**
 * HTTP headers the auth module needs from the project's server:
 *
 *  - Every response must carry X-Server-Time (authResponseHeaders()), also errors and
 *    public routes. The browser module uses it to correct the device clock, since signed
 *    requests are only accepted within signatures.maxClockSkewMs of the server time.
 *  - When the app is served from another origin (CORS), the server must allow the
 *    request headers AUTH_REQUEST_HEADERS and expose AUTH_EXPOSED_HEADERS.
 */
// DPoP carries the device proof (RFC 9449).
export const AUTH_REQUEST_HEADERS = ['Authorization', 'Content-Type', 'DPoP'];
export const AUTH_EXPOSED_HEADERS = ['X-Server-Time'];

export function authResponseHeaders() {
  return { 'X-Server-Time': String(Date.now()) };
}
