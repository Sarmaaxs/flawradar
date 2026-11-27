import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reproduce } from '../public/assets/js/reproduce.js';

test('header checks give a curl that prints only that header', () => {
  assert.equal(reproduce({ id: 'hsts' }, 'example.com'), "curl -sSI https://example.com/ | grep -i '^strict-transport-security'");
});

test('exposure findings test the paths that were reported, and nothing else', () => {
  const cmd = reproduce({ id: 'exposed-env', evidence: '/.env  (HTTP 200)\n/.env.local  (HTTP 200)' }, 'example.com');
  assert.ok(cmd.includes('https://example.com/.env') && cmd.includes('https://example.com/.env.local'));
  assert.equal(reproduce({ id: 'exposed-env', evidence: '' }, 'example.com'), null);
});

test('anything that is not a plain host name or path is refused, so no command can be injected', () => {
  for (const host of ["a.com; rm -rf /", 'a.com`id`', "a'b.com", 'a b.com', '', '$(id).com']) assert.equal(reproduce({ id: 'hsts' }, host), null, host);
  assert.equal(reproduce({ id: 'exposed-env', evidence: "/x'; id #  (HTTP 200)" }, 'example.com'), null);
});

test('unknown checks give no command', () => {
  assert.equal(reproduce({ id: 'something-new' }, 'example.com'), null);
});
