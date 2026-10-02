/**
 * Device key used to prove every API request comes from this browser: DPoP proofs
 * (RFC 9449, see server/dpop.js). Stored by ./store.js in the "app-auth" database.
 *
 * The private key is created as non-extractable: it can be used to sign in this
 * browser, but neither JavaScript nor DevTools can read or export it, so a copied
 * token is useless on another device.
 *
 * Keep the proof format in sync with server/dpop.js.
 */
const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };
const encoder = new TextEncoder();

/** Returns { privateKey, publicJwk }. Both are stored in IndexedDB (the key as-is). */
export async function createDeviceKey() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(KEY_ALGORITHM, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', publicKey);
  return { privateKey, publicJwk: { kty, crv, x, y } };
}

/**
 * Returns a DPoP proof (a JWT signed with the device key) for one request.
 *   url          the full request URL (a URL object)
 *   accessToken  the session token it travels with (ath); omit for login / sign-up
 *   bodyText     the exact body sent ('' when none)
 *   timestamp    ms since epoch, corrected with the server clock
 * Besides the standard claims it carries bh / qh: hashes of the body and the query.
 */
export async function createDpopProof({ privateKey, publicJwk }, { method, url, accessToken, bodyText = '', timestamp }) {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk };
  const payload = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: `${url.origin}${url.pathname}`,
    iat: Math.floor(timestamp / 1000),
    ...(accessToken ? { ath: await sha256Base64Url(accessToken) } : {}),
    // Every method that may carry a body gets bh, even with an empty body (as the server expects).
    ...(['GET', 'HEAD'].includes(method) ? {} : { bh: await sha256Base64Url(bodyText) }),
    ...(url.search ? { qh: await sha256Base64Url(url.search) } : {}),
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  // Web Crypto's ECDSA signature is r || s (64 bytes), exactly what JWS ES256 expects.
  const signature = await crypto.subtle.sign(SIGN_ALGORITHM, privateKey, encoder.encode(signingInput));
  return `${signingInput}.${toBase64Url(signature)}`;
}

async function sha256Base64Url(text) {
  return toBase64Url(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
}

function base64UrlJson(value) {
  return toBase64Url(encoder.encode(JSON.stringify(value)));
}

function toBase64Url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
