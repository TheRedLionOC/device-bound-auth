/**
 * Device-bound requests (similar to OAuth DPoP).
 *
 * At login the browser generates an ECDSA P-256 key pair whose private key cannot
 * be exported, and sends the public key, which is stored with the session. Every
 * authenticated request carries:
 *   X-Device-Timestamp: ms since epoch
 *   X-Device-Signature: base64url ECDSA signature of
 *       `${METHOD}\n${path + query}\n${timestamp}\n${base64url(sha256(body))}`
 * A token copied to another device cannot produce valid signatures.
 *
 * Keep the message format in sync with browser/device-key.js.
 */
import { authConfig } from './config.js';
import { base64UrlToBytes, bytesToBase64Url } from './encoding.js';
import { AuthError } from './errors.js';

const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };

// Imported public keys per session, reused while the Worker instance is alive.
const keyCache = new Map();
const MAX_CACHED_KEYS = 1000;

/** Validates a public key sent at login and returns it as a JSON string for storage. */
export async function normalizePublicKey(jwk) {
  const invalid = new AuthError(400, 'A valid device public key is required');
  if (!jwk || typeof jwk !== 'object' || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw invalid;
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw invalid;

  const publicKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  try {
    await crypto.subtle.importKey('jwk', publicKey, KEY_ALGORITHM, false, ['verify']);
  } catch {
    throw invalid;
  }
  return JSON.stringify(publicKey);
}

/** Throws a 401 unless the request is signed by the session's device key. */
export async function verifyDeviceProof(request, url, sessionId, publicKeyJson) {
  const timestamp = Number(request.headers.get('X-Device-Timestamp'));
  const signature = request.headers.get('X-Device-Signature');
  if (!timestamp || !signature) throw new AuthError(401, 'Missing device signature');

  // Only accepted this close to the server time, so a copied request cannot be replayed
  // later. Clients correct their clock with the X-Server-Time header (see headers.js).
  if (Math.abs(Date.now() - timestamp) > authConfig().signatures.maxClockSkewMs) {
    throw new AuthError(401, 'Device clock is out of sync', { code: 'clock_skew' });
  }

  const key = await getPublicKey(sessionId, publicKeyJson);
  const body = ['GET', 'HEAD'].includes(request.method) ? new ArrayBuffer(0) : await request.clone().arrayBuffer();
  const message = await proofMessage(request.method, url.pathname + url.search, timestamp, body);

  let valid = false;
  try {
    valid = await crypto.subtle.verify(SIGN_ALGORITHM, key, base64UrlToBytes(signature), message);
  } catch {
    valid = false;
  }
  if (!valid) throw new AuthError(401, 'Invalid device signature');
}

async function getPublicKey(sessionId, publicKeyJson) {
  let key = keyCache.get(sessionId);
  if (!key) {
    key = await crypto.subtle.importKey('jwk', JSON.parse(publicKeyJson), KEY_ALGORITHM, false, ['verify']);
    if (keyCache.size >= MAX_CACHED_KEYS) keyCache.clear();
    keyCache.set(sessionId, key);
  }
  return key;
}

async function proofMessage(method, path, timestamp, body) {
  const bodyHash = bytesToBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', body)));
  return new TextEncoder().encode(`${method}\n${path}\n${timestamp}\n${bodyHash}`);
}
