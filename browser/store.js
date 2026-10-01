/**
 * Auth storage: its own IndexedDB database (storageName, "app-auth" by default),
 * separate from app data.
 *
 * Holds only the session (token + user) and the device key. Keeping it apart means
 * the data database can be cleared, rebuilt or versioned without logging the user
 * out, and online-only projects can use this module without any data database.
 *
 * Uses the native IndexedDB API (no library): one store, read / write / clear.
 */
import { authConfig } from './config.js';

const DB_VERSION = 1;
const STORE = 'kv';

let dbPromise;

/** Turns an IndexedDB request into a promise. */
function done(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function openAuthDb() {
  if (dbPromise) return dbPromise;

  const request = indexedDB.open(authConfig().storageName, DB_VERSION);
  request.onupgradeneeded = () => {
    const db = request.result;
    if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'key' });
  };
  dbPromise = done(request).then((db) => {
    // A newer app version (another tab) needs to upgrade this database: let it.
    db.onversionchange = () => {
      db.close();
      dbPromise = null;
      window.dispatchEvent(new CustomEvent('auth:outdated'));
    };
    return db;
  });
  dbPromise.catch(() => {
    dbPromise = null;
  });
  return dbPromise;
}

/** Runs `action(store)` in a transaction and resolves with its result once committed. */
async function withStore(mode, action) {
  const transaction = (await openAuthDb()).transaction(STORE, mode);
  const result = done(action(transaction.objectStore(STORE)));
  await new Promise((resolve, reject) => {
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  return result;
}

async function read(key) {
  return (await withStore('readonly', (store) => store.get(key)))?.value ?? null;
}

async function write(key, value) {
  await withStore('readwrite', (store) => store.put({ key, value }));
}

/** { token, issuedAt, user } or null. */
export const readSession = () => read('session');
export const writeSession = (session) => write('session', session);

/** { privateKey } (a non-extractable CryptoKey, see device-key.js) or null. */
export const readDeviceKey = () => read('deviceKey');
export const writeDeviceKey = (deviceKey) => write('deviceKey', deviceKey);

/** Deletes the session and the device key from this browser. */
export async function clearAuth() {
  await withStore('readwrite', (store) => store.clear());
}
