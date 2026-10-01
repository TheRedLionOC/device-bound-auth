import { authConfig } from './config.js';
import { base64ToBytes, bytesToBase64, timingSafeEqual } from './encoding.js';

const HASH_BITS = 256;
// Hashes made before the iteration count was stored with them used this.
const LEGACY_ITERATIONS = 100_000;

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    HASH_BITS,
  );
  return new Uint8Array(bits);
}

/**
 * Returns { hash, salt } as strings for the password_hash and password_salt columns.
 * The salt carries the iteration count ("600000$<base64 salt>"), so changing
 * configureAuth({ passwords: { iterations } }) never breaks existing passwords.
 */
export async function hashPassword(password, iterations = authConfig().passwords.iterations) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, iterations);
  return { hash: bytesToBase64(hash), salt: `${iterations}$${bytesToBase64(salt)}` };
}

export async function verifyPassword(password, hash, salt) {
  const [iterations, encodedSalt] = salt.includes('$') ? salt.split('$') : [LEGACY_ITERATIONS, salt];
  const derived = await derive(password, base64ToBytes(encodedSalt), Number(iterations));
  return timingSafeEqual(derived, base64ToBytes(hash));
}
