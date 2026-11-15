import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAllowValue, allowInstructions, checkAllow } from '../server/allow.js';

describe('parseAllowValue', () => {
  test('accepts plain flawradar-allow=1', () => {
    assert.deepEqual(parseAllowValue('flawradar-allow=1'), { contact: null });
    assert.deepEqual(parseAllowValue('  flawradar-allow=1  '), { contact: null });
  });

  test('accepts contact parameter', () => {
    assert.deepEqual(parseAllowValue('flawradar-allow=1; contact=security@example.com'), {
      contact: 'security@example.com',
    });
  });

  test('rejects missing or wrong values', () => {
    assert.equal(parseAllowValue(''), null);
    assert.equal(parseAllowValue('flawradar-allow=0'), null);
    assert.equal(parseAllowValue('flawradar-verify=abc'), null);
    assert.equal(parseAllowValue(null), null);
  });

  test('is case-insensitive on the key', () => {
    assert.ok(parseAllowValue('FLAWRADAR-ALLOW=1'));
  });
});

describe('allowInstructions', () => {
  test('returns dns and file shapes', () => {
    const i = allowInstructions('example.com');
    assert.equal(i.dns.name, '_flawradar.example.com');
    assert.equal(i.dns.value, 'flawradar-allow=1');
    assert.equal(i.file.path, '/.well-known/flawradar-allow.txt');
  });
});

describe('checkAllow', () => {
  test('finds allow in DNS TXT', async () => {
    const resolver = {
      resolveTxt: async () => [['flawradar-allow=1; contact=sec@ex.com']],
    };
    const target = { host: 'example.com', hostUrl: 'example.com', isIp: false };
    const r = await checkAllow(target, { resolver, ports: { https: 443, http: 80 } });
    assert.equal(r.allowed, true);
    assert.equal(r.method, 'dns');
    assert.equal(r.contact, 'sec@ex.com');
  });

  test('returns not allowed when nothing is published', async () => {
    const resolver = {
      resolveTxt: async () => {
        const err = new Error('ENODATA');
        err.code = 'ENODATA';
        throw err;
      },
    };
    // Avoid real network for the file probe by using an IP target (skips DNS already done)
    // and a host that won't be fetched — we only care that DNS miss + file miss = false.
    // For IP targets DNS is skipped; file will fail quickly on private/unreachable in tests.
    // Use a stub by making isIp true so only file path is tried, and accept failure.
    const target = { host: '127.0.0.1', hostUrl: '127.0.0.1', isIp: true };
    const r = await checkAllow(target, { resolver, ports: { https: 443, http: 80 } });
    assert.equal(r.allowed, false);
    assert.ok(Array.isArray(r.tried));
  });
});
