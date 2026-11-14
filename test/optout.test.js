import test from 'node:test';
import assert from 'node:assert/strict';

process.env.WSEC_BLOCKED_HOSTS = 'blocked.example, .Opted-Out.example.org';
process.env.WSEC_DB = ':memory:';

const { isOptedOut, resolvePublic } = await import('../server/scanner/net.js');

test('hosts that opted out are refused, including their subdomains', async () => {
  assert.equal(isOptedOut('blocked.example'), true);
  assert.equal(isOptedOut('www.blocked.example'), true);
  assert.equal(isOptedOut('BLOCKED.EXAMPLE'), true);
  assert.equal(isOptedOut('opted-out.example.org'), true);
  assert.equal(isOptedOut('a.b.opted-out.example.org'), true);
  assert.equal(isOptedOut('notblocked.example'), false);
  assert.equal(isOptedOut('blocked.example.com'), false);
  await assert.rejects(resolvePublic('www.blocked.example'), (err) => err.code === 'opted_out');
});