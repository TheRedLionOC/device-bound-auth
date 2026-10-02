/**
 * Calls the project's API (base URL set with configureAuth) with the session token and a
 * DPoP proof from the device key (RFC 9449, see device-key.js) on every request.
 */
import { authConfig } from './config.js';
import { createDpopProof } from './device-key.js';
import { readDeviceKey, readSession } from './store.js';

export class ApiError extends Error {
  /** `status` is 0 when the network is unavailable. */
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

// Difference between the server clock (X-Server-Time header) and this device's clock.
// Proofs must be close to the server time, and device clocks can be wrong.
let clockOffsetMs = 0;

/**
 * Calls the API with the session token, signing the request with the device key.
 * `auth: false` sends it without credentials (e.g. login); `proofKey` ({ privateKey,
 * publicJwk }) then adds a DPoP proof without a token, binding a new session to that key.
 * Dispatches `auth:expired` on 401, with `detail.code` = 'session_expired' or
 * 'session_revoked' (see server/authenticate.js).
 */
export async function api(path, { method = 'GET', body, auth = true, proofKey } = {}) {
  const [session, deviceKey] = auth ? await Promise.all([readSession(), readDeviceKey()]) : [null, null];

  // A session whose device key is missing or incomplete (e.g. part of the site data was
  // cleared) cannot prove requests. End it like an expired one (local data is kept) instead
  // of sending requests that fail with a 401.
  if (session?.token && !deviceKey?.publicJwk) {
    window.dispatchEvent(
      new CustomEvent('auth:expired', { detail: { code: 'session_expired', reason: 'device_key_missing' } }),
    );
    throw new ApiError(401, 'This device lost its session key; log in again', { code: 'device_key_missing' });
  }

  const key = session?.token ? deviceKey : proofKey;
  let result = await send(path, method, body, session?.token, key);

  // The device clock was too far off: retry once with the offset learned from the response.
  if (result.response.status === 401 && result.data?.details?.code === 'clock_skew') {
    result = await send(path, method, body, session?.token, key);
  }

  const { response, data } = result;
  if (!response.ok) {
    if (response.status === 401 && session?.token) {
      window.dispatchEvent(new CustomEvent('auth:expired', { detail: { code: data?.details?.code } }));
    }
    throw new ApiError(response.status, data?.error ?? response.statusText, data?.details);
  }
  return data;
}

async function send(path, method, body, token, key) {
  const url = new URL(`${authConfig().apiUrl}${path}`);
  const bodyText = body === undefined ? undefined : JSON.stringify(body);
  const timestamp = Date.now() + clockOffsetMs;

  const headers = {};
  if (bodyText !== undefined) headers['Content-Type'] = 'application/json';
  if (key) {
    // The DPoP proof, and the token (if any) with the DPoP scheme.
    if (token) headers.Authorization = `DPoP ${token}`;
    headers.DPoP = await createDpopProof(key, { method, url, accessToken: token, bodyText: bodyText ?? '', timestamp });
  }

  let response;
  try {
    response = await fetch(url, { method, headers, body: bodyText });
  } catch {
    throw new ApiError(0, authConfig().offlineMessage);
  }

  const serverTime = Number(response.headers.get('X-Server-Time'));
  if (serverTime) clockOffsetMs = serverTime - Date.now();

  const data = await response.json().catch(() => null);
  return { response, data };
}
