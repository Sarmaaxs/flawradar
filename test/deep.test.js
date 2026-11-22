import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDeepProbes } from '../server/scanner/deep.js';

const serve = (files) => async (path) => (path in files ? { res: { status: 200, headers: {}, body: files[path] } } : { res: { status: 404, headers: {}, body: '' } });

test('new probes flag only real signatures', async () => {
  const r = await runDeepProbes(serve({
    '/.npmrc': '//registry.npmjs.org/:_authToken=abc',
    '/id_rsa': '-----BEGIN OPENSSH PRIVATE KEY-----\nabc',
    '/actuator/env': '{"activeProfiles":[],"propertySources":[]}',
    '/phpmyadmin/': '<html><title>phpMyAdmin</title><form></form>',
  }), { delayMs: 0 });
  const paths = r.hits.map((h) => h.path).sort();
  assert.deepEqual(paths, ['/.npmrc', '/actuator/env', '/id_rsa', '/phpmyadmin/']);
  assert.ok(r.hits.filter((h) => h.group === 'keys').length === 2);
});

test('a site that answers 200 to everything is not flagged', async () => {
  const page = '<!doctype html><html><body>Welcome. phpMyAdmin is not here. adminer</body></html>';
  const all = async () => ({ res: { status: 200, headers: {}, body: page } });
  const r = await runDeepProbes(all, { delayMs: 0 });
  assert.equal(r.hits.length, 0);
});
