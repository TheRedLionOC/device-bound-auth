/**
 * DPoP proofs (RFC 9449, OAuth 2.0 Demonstrating Proof of Possession).
 *
 * Every authenticated request carries
 *   Authorization: DPoP <session token>
 *   DPoP: <proof>
 * where the proof is a JWT signed by the device's non-extractable ECDSA P-256 key, with the
 * public key in its header:
 *   header  { typ: 'dpop+jwt', alg: 'ES256', jwk }
 *   payload { jti, htm, htu, iat, ath }            standard claims (RFC 9449 §4.2)
 *           { bh, qh }                             extensions: SHA-256 (base64url) of the
 *                                                  request body and of the query string
 * The standard covers method and URL but not the body or the query. The extension claims
 * (allowed by the RFC; standard verifiers ignore them) bind those too, so a captured proof
 * cannot be reused with other data. signatures.requireBodyAndQueryHashes makes them optional
 * for clients that send plain DPoP. Session tokens carry cnf.jkt, the thumbprint of the key.
 * Login and sign-up send a proof too (without ath): the new session is bound to its key.
 *
 * Keep in sync with browser/device-key.js.
 */
import { EmbeddedJWK, calculateJwkThumbprint, jwtVerify } from 'jose';
import { authConfig } from './config.js';
import { bytesToBase64Url } from './encoding.js';
import { AuthError } from './errors.js';

const MAX_JTI_LENGTH = 128;

const invalid = (message) => new AuthError(401, message, { code: 'invalid_dpop_proof' });

/** base64url(SHA-256(data)), data being a string or bytes. */
export async function sha256Base64Url(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

/** The public key of a verified proof, as stored with the session (sessions.public_key). */
export function storedPublicKey({ kty, crv, x, y }) {
  return JSON.stringify({ kty, crv, x, y });
}

/** JWK thumbprint (RFC 7638) of a P-256 public key, as used in cnf.jkt. */
export function jwkThumbprint({ kty, crv, x, y }) {
  return calculateJwkThumbprint({ kty, crv, x, y }, 'sha256');
}

// Thumbprints of the keys stored with sessions, reused while the instance is alive.
const thumbprintCache = new Map();
const MAX_CACHED_THUMBPRINTS = 1000;

/** Thumbprint of a session's stored public key (sessions.public_key, a JWK as JSON). */
export async function sessionKeyThumbprint(publicKeyJson) {
  let jkt = thumbprintCache.get(publicKeyJson);
  if (!jkt) {
    jkt = await jwkThumbprint(JSON.parse(publicKeyJson));
    if (thumbprintCache.size >= MAX_CACHED_THUMBPRINTS) thumbprintCache.clear();
    thumbprintCache.set(publicKeyJson, jkt);
  }
  return jkt;
}

/**
 * Verifies the request's DPoP proof (RFC 9449 §4.3, plus bh/qh) and returns { jwk, jkt }.
 * `accessToken`: the token the proof must be bound to (ath); null when there is none yet
 * (login, sign-up). Throws a 401 with details.code 'invalid_dpop_proof' or 'clock_skew'.
 */
export async function verifyDpopProof(request, env, { accessToken = null } = {}) {
  const { signatures } = authConfig();

  // 1-2. Exactly one well-formed proof (several headers arrive joined by commas).
  const proof = request.headers.get('DPoP');
  if (!proof) throw invalid('Missing DPoP proof');
  if (proof.includes(',')) throw invalid('Only one DPoP proof is allowed');

  // 3-7. typ dpop+jwt, ES256, public JWK in the header, valid signature with that key.
  let payload;
  let protectedHeader;
  try {
    ({ payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: ['ES256'],
    }));
  } catch {
    throw invalid('Invalid DPoP proof');
  }
  const { jwk } = protectedHeader;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw invalid('DPoP key must be P-256');

  // 8. Method and URL (without query and fragment) of this request.
  const url = new URL(request.url);
  if (payload.htm !== request.method) throw invalid('DPoP proof is for another method');
  let htu;
  try {
    htu = new URL(payload.htu);
  } catch {
    throw invalid('Invalid DPoP htu');
  }
  const origin = signatures.origin ?? url.origin;
  if (htu.origin !== origin || htu.pathname !== url.pathname) throw invalid('DPoP proof is for another URL');

  // 11. Recent enough. Clients correct their clock with X-Server-Time (see headers.js).
  if (typeof payload.iat !== 'number' || Math.abs(Date.now() - payload.iat * 1000) > signatures.maxClockSkewMs) {
    throw new AuthError(401, 'Device clock is out of sync', { code: 'clock_skew' });
  }
  if (typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > MAX_JTI_LENGTH) {
    throw invalid('Invalid DPoP jti');
  }

  // 12. Bound to the access token it travels with.
  if (accessToken !== null && payload.ath !== (await sha256Base64Url(accessToken))) {
    throw invalid('DPoP proof is for another token');
  }

  // Extensions: body and query. Checked whenever present; required unless configured not to.
  const hasBody = !['GET', 'HEAD'].includes(request.method);
  if (payload.bh !== undefined) {
    const body = hasBody ? new Uint8Array(await request.clone().arrayBuffer()) : new Uint8Array(0);
    if (payload.bh !== (await sha256Base64Url(body))) throw invalid('DPoP proof is for another body');
  } else if (hasBody && signatures.requireBodyAndQueryHashes) {
    throw invalid('DPoP proof must cover the body (bh)');
  }
  if (payload.qh !== undefined) {
    if (payload.qh !== (await sha256Base64Url(url.search))) throw invalid('DPoP proof is for another query');
  } else if (url.search && signatures.requireBodyAndQueryHashes) {
    throw invalid('DPoP proof must cover the query (qh)');
  }

  // Optional replay detection: each proof used once.
  if (signatures.useJti) {
    const expiresAt = payload.iat * 1000 + signatures.maxClockSkewMs;
    if (!(await signatures.useJti({ jti: payload.jti, expiresAt, env }))) throw invalid('DPoP proof was already used');
  }

  return { jwk, jkt: await jwkThumbprint(jwk) };
}
