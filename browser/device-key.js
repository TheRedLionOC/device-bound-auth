/**
 * Device key used to sign every API request (see server/device-proof.js).
 * Stored by ./store.js in the "app-auth" database.
 *
 * The private key is created as non-extractable: it can be used to sign in this
 * browser, but neither JavaScript nor DevTools can read or export it, so a copied
 * token is useless on another device.
 *
 * Keep the signed message format in sync with the backend.
 */
const KEY_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256' };
const encoder = new TextEncoder();

/** Returns { privateKey, publicJwk }. The private key is stored as-is in IndexedDB. */
export async function createDeviceKey() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(KEY_ALGORITHM, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', publicKey);
  return { privateKey, publicJwk: { kty, crv, x, y } };
}

/** Returns the headers that prove the request comes from this device. */
export async function signRequest(privateKey, method, path, bodyText, timestamp) {
  const bodyHash = toBase64Url(await crypto.subtle.digest('SHA-256', encoder.encode(bodyText)));
  const message = encoder.encode(`${method}\n${path}\n${timestamp}\n${bodyHash}`);
  const signature = await crypto.subtle.sign(SIGN_ALGORITHM, privateKey, message);
  return {
    'X-Device-Timestamp': String(timestamp),
    'X-Device-Signature': toBase64Url(signature),
  };
}

function toBase64Url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
