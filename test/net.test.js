import test from 'node:test';
import assert from 'node:assert/strict';

delete process.env.WSEC_ALLOW_PRIVATE;
const { isPublicIp, parseTarget, resolvePublic } = await import('../server/scanner/net.js');

test('isPublicIp accepts public addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPublicIp(ip), true, ip);
  }
});

test('isPublicIp rejects private and reserved addresses', () => {
  for (const ip of [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '2001:db8::1', 'ff02::1',
  ]) {
    assert.equal(isPublicIp(ip), false, ip);
  }
  assert.equal(isPublicIp('not an ip'), false);
  assert.equal(isPublicIp('172.32.0.1'), true);
});

test('parseTarget normalises what people type', () => {
  assert.equal(parseTarget('example.com').host, 'example.com');
  assert.equal(parseTarget('  EXAMPLE.com  ').host, 'example.com');
  assert.equal(parseTarget('https://Example.com/some/path?q=1#x').host, 'example.com');
  assert.equal(parseTarget('http://sub.example.co.uk').host, 'sub.example.co.uk');
  assert.equal(parseTarget('example.com.').host, 'example.com');
});

test('parseTarget refuses bad input', () => {
  const bad = [
    '', '   ', null, undefined, 42, 'x'.repeat(400),
    'ftp://example.com', 'file:///etc/passwd', 'javascript:alert(1)',
    'https://user:pass@example.com', 'exa mple.com', 'example..com', '-bad.example.com', 'under_score.example.com',
  ];
  for (const input of bad) assert.throws(() => parseTarget(input), { name: 'AppError' }, String(input));
});

test('parseTarget refuses internal names, IP literals and custom ports', () => {
  for (const input of [
    'localhost', 'intranet', 'printer.local', 'db.internal', 'a.localhost',
    '127.0.0.1', '10.0.0.5', 'http://[::1]/', '169.254.169.254', 'http://2130706433/', 'http://0x7f.1/',
    'example.com:8080', 'https://example.com:22/',
  ]) {
    assert.throws(() => parseTarget(input), { name: 'AppError' }, input);
  }
});

test('resolvePublic refuses names that resolve to a private address', async () => {
  await assert.rejects(resolvePublic('localhost'), (err) => err.code === 'blocked_target');
  await assert.rejects(resolvePublic('127.0.0.1'), (err) => err.code === 'blocked_target');
  await assert.rejects(resolvePublic('::1'), (err) => err.code === 'blocked_target');
});
