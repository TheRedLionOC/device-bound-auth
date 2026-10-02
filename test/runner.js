/**
 * The same test files run on Bun (`bun test`, bun:test) and on Node (`node --test`,
 * node:test plus a small expect() with the matchers the suite uses).
 */
import assert from 'node:assert/strict';

export const isBun = typeof Bun !== 'undefined';

function expect(actual) {
  return {
    toBe: (expected) => assert.equal(actual, expected),
    toEqual: (expected) => assert.deepEqual(actual, expected),
    toMatchObject: (expected) => {
      for (const [key, value] of Object.entries(expected)) assert.deepEqual(actual?.[key], value, `property ${key}`);
    },
    toHaveLength: (length) => assert.equal(actual?.length, length),
    toBeGreaterThan: (value) => assert.ok(actual > value, `${actual} > ${value}`),
    toThrow: (message) => assert.throws(actual, (err) => !message || String(err.message).includes(message)),
  };
}

async function load() {
  if (isBun) return import('bun:test');
  const t = await import('node:test');
  return { describe: t.describe, test: t.test, beforeAll: t.before, afterAll: t.after, expect };
}

export const { describe, test, beforeAll, afterAll, expect: expectFn } = await load();
export { expectFn as expect };
