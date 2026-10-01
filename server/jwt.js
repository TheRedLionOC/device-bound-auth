/**
 * Session tokens (HS256 JWT) through the `jose` library, a widely used and audited
 * implementation of the JWT/JOSE standards (https://github.com/panva/jose).
 */
import { SignJWT, errors, jwtVerify } from 'jose';

const ALGORITHM = 'HS256';
const encoder = new TextEncoder();

/** Signs an HS256 JWT with `payload` that expires after `expiresInSeconds`. */
export function signJwt(payload, secret, expiresInSeconds) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: ALGORITHM, typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + expiresInSeconds)
    .sign(encoder.encode(secret));
}

/**
 * Returns { payload } if the token is valid and not expired, otherwise
 * { error: 'expired' } (genuine but too old) or { error: 'invalid' } (forged,
 * malformed, another algorithm, or signed with a previous JWT_SECRET).
 */
export async function verifyJwt(token, secret) {
  try {
    const { payload } = await jwtVerify(token, encoder.encode(secret), {
      algorithms: [ALGORITHM],
      requiredClaims: ['exp'],
    });
    return { payload };
  } catch (err) {
    return { error: err instanceof errors.JWTExpired ? 'expired' : 'invalid' };
  }
}
