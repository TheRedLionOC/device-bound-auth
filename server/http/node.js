/**
 * Runs a fetch-style handler (Request → Response, like a Cloudflare Worker or Bun.serve)
 * on Node's HTTP server or Express, so the auth module works there unchanged:
 *
 *   import { createServer } from 'node:http';
 *   import { nodeHandler } from 'device-bound-auth/server/http/node';
 *   createServer(nodeHandler((request, req) => handle(request, env(req)))).listen(3000);
 *
 *   // Express: mount it BEFORE express.json() (see below)
 *   app.use(nodeHandler((request, req) => handle(request, env(req))));
 *
 * The second argument is Node's request, e.g. for the client IP of a rate limit:
 * req.socket.remoteAddress (or a header set by your proxy).
 *
 * Signed requests cover the exact body bytes, so the raw body must reach the handler.
 * If a body parser such as express.json() already consumed it, the original bytes are gone
 * and this throws: mount nodeHandler before body parsers, or on its own path.
 */
import { Readable } from 'node:stream';

export function nodeHandler(fetchHandler, { trustProxy = false } = {}) {
  return async (req, res, next) => {
    try {
      const response = await fetchHandler(toRequest(req, trustProxy), req);
      await writeResponse(res, response);
    } catch (err) {
      if (next) next(err);
      else {
        console.error(err);
        if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    }
  };
}

function toRequest(req, trustProxy) {
  const forwarded = trustProxy && req.headers['x-forwarded-proto']?.split(',')[0].trim();
  const protocol = forwarded || (req.socket.encrypted ? 'https' : 'http');
  const url = new URL(req.originalUrl ?? req.url, `${protocol}://${req.headers.host ?? 'localhost'}`);

  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  }

  const hasBody = !['GET', 'HEAD'].includes(req.method);
  if (hasBody && req.readableEnded) {
    throw new Error(
      'device-bound-auth: the request body was already read (e.g. by express.json()). ' +
        'Mount nodeHandler before body parsers: signed requests need the exact body bytes.',
    );
  }
  return new Request(url, {
    method: req.method,
    headers,
    body: hasBody ? Readable.toWeb(req) : undefined,
    duplex: 'half',
  });
}

async function writeResponse(res, response) {
  const headers = {};
  response.headers.forEach((value, name) => {
    headers[name] = value;
  });
  res.writeHead(response.status, response.statusText, headers);
  res.end(Buffer.from(await response.arrayBuffer()));
}
