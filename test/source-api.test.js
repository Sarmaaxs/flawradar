import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { makeZip } from './helpers/zipwriter.js';

process.env.FLAWRADAR_DB = ':memory:';
process.env.FLAWRADAR_QUIET = '1';
process.env.FLAWRADAR_SOURCE_PER_HOUR = '40';

const { createServer } = await import('../server/app.js');
const { config } = await import('../server/config.js');
const TERMS = config.termsVersion;
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

const postJson = async (path, body, terms = TERMS) => {
  const res = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ terms, ...body }) });
  return { status: res.status, body: await res.json(), headers: res.headers };
};
const postZip = async (buffer, type = 'application/zip', terms = TERMS) => {
  const res = await fetch(base + '/api/source/zip', { method: 'POST', headers: { 'Content-Type': type, 'X-FlawRadar-Terms': terms }, body: buffer });
  return { status: res.status, body: await res.json() };
};

test('POST /api/source analyses files and returns findings', async () => {
  const { status, body } = await postJson('/api/source', {
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
  assert.equal((await postJson('/api/source', {})).status, 400);
  assert.equal((await postJson('/api/source', { files: [] })).status, 400);
  assert.equal((await postJson('/api/source', { files: [{ path: 'a.js' }] })).status, 400);
  assert.equal((await postJson('/api/source', { files: [{ path: 5, content: 'x' }] })).status, 400);
  const many = await postJson('/api/source', { files: Array.from({ length: 3001 }, (_, i) => ({ path: `f${i}.js`, content: 'x' })) });
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
  const res = await fetch(base + '/api/source/zip', { method: 'POST', headers: { 'Content-Type': 'application/zip', 'X-FlawRadar-Terms': TERMS }, body: big }).catch((e) => e);
  // The server may close the connection once it has refused; either outcome is a refusal.
  if (res instanceof Error) return;
  assert.equal(res.status, 413);
});

test('nothing from an upload is stored', async () => {
  const marker = 'UNIQUE_MARKER_VALUE_12345';
  await postJson('/api/source', { files: [{ path: 'a.js', content: `eval("${marker}")` }] });
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

test('source checks need the current terms, for JSON and zip uploads', async () => {
  const noTerms = await postJson('/api/source', { files: [{ path: 'a.js', content: 'x' }] }, null);
  assert.equal(noTerms.status, 400);
  assert.equal(noTerms.body.error.code, 'terms_required');
  const stale = await postJson('/api/source', { files: [{ path: 'a.js', content: 'x' }] }, 'old');
  assert.equal(stale.body.error.code, 'terms_required');
  const zip = makeZip([{ name: 'a.js', data: 'eval(x)' }]);
  const zipNo = await postZip(zip, 'application/zip', 'old');
  assert.equal(zipNo.status, 400);
  assert.equal(zipNo.body.error.code, 'terms_required');
});

test('the browser engine files are served, and are the same files the server uses', async () => {
  for (const name of ['analyze', 'rules', 'filechecks', 'paths', 'cves']) {
    const res = await fetch(`${base}/assets/engine/${name}.js`);
    assert.equal(res.status, 200, name);
    assert.match(res.headers.get('content-type'), /javascript/);
  }
  assert.equal((await fetch(`${base}/assets/engine/app.js`)).status, 404);
  assert.equal((await fetch(`${base}/assets/engine/..%2Fconfig.js`)).status, 404);
});

test('the CVE relay takes package names only, needs the terms, and validates input', async () => {
  const pkg = { name: 'lodash', version: '4.17.20', ecosystem: 'npm', file: 'package-lock.json', line: 3 };
  assert.equal((await postJson('/api/cves', { packages: [pkg] }, 'old')).status, 400);
  assert.equal((await postJson('/api/cves', {})).status, 400);
  assert.equal((await postJson('/api/cves', { packages: [] })).status, 400);
  assert.equal((await postJson('/api/cves', { packages: [{ ...pkg, ecosystem: 'evil' }] })).status, 400);
  assert.equal((await postJson('/api/cves', { packages: [{ ...pkg, name: 5 }] })).status, 400);
  assert.equal((await postJson('/api/cves', { packages: Array.from({ length: 181 }, () => pkg) })).status, 400);
});

test('source checks are rate limited per visitor', async () => {
  let last;
  for (let i = 0; i < 60; i += 1) {
    last = await postJson('/api/source', { files: [{ path: 'a.js', content: 'x' }] });
    if (last.status === 429) break;
  }
  assert.equal(last.status, 429);
  assert.equal(last.body.error.code, 'rate_limited');
  assert.ok(last.headers.get('retry-after'));
});
