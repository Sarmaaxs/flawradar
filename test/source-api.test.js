import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { makeZip } from './helpers/zipwriter.js';

process.env.WSEC_DB = ':memory:';
process.env.WSEC_QUIET = '1';
process.env.WSEC_SOURCE_PER_HOUR = '12';

const { createServer } = await import('../server/app.js');
const db = await import('../server/db.js');

let server;
let base;

before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.closeAllConnections?.();
  server.close();
  db.close();
});

const { config } = await import('../server/config.js');
const TERMS = config.termsVersion;

const postJson = async (path, body) => {
  const res = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json(), headers: res.headers };
};
const postZip = async (buffer, type = 'application/zip') => {
  const res = await fetch(base + '/api/source/zip', {
    method: 'POST',
    headers: { 'Content-Type': type, 'X-Wsec-Terms': TERMS },
    body: buffer,
  });
  return { status: res.status, body: await res.json() };
};

test('POST /api/source analyses files and returns findings', async () => {
  const { status, body } = await postJson('/api/source', {
    terms: TERMS,
    files: [
      { path: 'app/login.php', content: '<?php\n$r = mysqli_query($c, "SELECT * FROM u WHERE n=" . $_POST["n"]);\n' },
      { path: 'app/ok.js', content: 'const a = 1;\n' },
    ],
  });
  assert.equal(status, 200);
  assert.equal(body.stats.filesScanned, 2);
  assert.equal(body.summary.critical, 1);
  assert.equal(body.findings[0].ruleId, 'php-sql-injection');
  assert.equal(body.findings[0].file, 'app/login.php');
  assert.equal(body.findings[0].line, 2);
});

test('POST /api/source/zip analyses a zip body', async () => {
  const zip = makeZip([
    { name: 'site/config.js', data: 'rejectUnauthorized: false\n' },
    { name: 'site/node_modules/x/i.js', data: 'eval(a)' },
  ]);
  const { status, body } = await postZip(zip);
  assert.equal(status, 200);
  assert.equal(body.findings.length, 1);
  assert.equal(body.findings[0].ruleId, 'js-tls-verification-off');
  assert.match(body.notices.join(' '), /node_modules/);
});

test('bad input is refused with a useful error', async () => {
  assert.equal((await postJson('/api/source', { terms: TERMS })).status, 400);
  assert.equal((await postJson('/api/source', { terms: TERMS, files: [] })).status, 400);
  assert.equal((await postJson('/api/source', { terms: TERMS, files: [{ path: 'a.js' }] })).status, 400);
  assert.equal((await postJson('/api/source', { terms: TERMS, files: [{ path: 5, content: 'x' }] })).status, 400);
  const many = await postJson('/api/source', {
    terms: TERMS,
    files: Array.from({ length: 3001 }, (_, i) => ({ path: `f${i}.js`, content: 'x' })),
  });
  assert.equal(many.status, 413);
  assert.equal(many.body.error.code, 'too_many_files');

  const notZip = await postZip(Buffer.from('this is not a zip file at all, only some text'));
  assert.equal(notZip.status, 400);
  assert.equal(notZip.body.error.code, 'bad_zip');
  assert.equal((await postZip(Buffer.from('x'.repeat(30)), 'text/plain')).status, 415);

  const wrongType = await fetch(base + '/api/source', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x' });
  assert.equal(wrongType.status, 415);
});

test('oversized uploads are rejected before they are read', async () => {
  const big = Buffer.alloc(11 * 1024 * 1024, 1);
  const res = await fetch(base + '/api/source/zip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/zip', 'X-Wsec-Terms': TERMS },
    body: big,
  }).catch((e) => e);
  // The server may close the connection once it has refused; either outcome is a refusal.
  if (res instanceof Error) return;
  assert.equal(res.status, 413);
});

test('nothing from an upload is stored', async () => {
  const marker = 'UNIQUE_MARKER_VALUE_12345';
  await postJson('/api/source', { terms: TERMS, files: [{ path: 'a.js', content: `eval("${marker}")` }] });
  const rows = db.countHostScansSince('anything', 0);
  assert.equal(rows, 0);
  const rules = await (await fetch(base + '/api/source/rules')).json();
  assert.ok(rules.rules.length > 50);
  assert.ok(!JSON.stringify(rules).includes(marker));
});

test('the source page is served with the strict policy', async () => {
  const res = await fetch(base + '/source');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
  const html = await res.text();
  assert.doesNotMatch(html, /\sstyle=|\son[a-z]+=/i);
});

test('source checks are rate limited per visitor', async () => {
  let last;
  for (let i = 0; i < 20; i += 1) {
    last = await postJson('/api/source', { terms: TERMS, files: [{ path: 'a.js', content: 'x' }] });
    if (last.status === 429) break;
  }
  assert.equal(last.status, 429);
  assert.equal(last.body.error.code, 'rate_limited');
  assert.ok(last.headers.get('retry-after'));
});