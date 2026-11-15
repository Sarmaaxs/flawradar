import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

process.env.FLAWRADAR_ALLOW_PRIVATE = '1';
process.env.FLAWRADAR_DB = ':memory:';

const { parseTarget } = await import('../server/scanner/net.js');
const { runScan } = await import('../server/scanner/scan.js');

let hasOpenssl = true;
try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  hasOpenssl = false;
}

let server;
let port;
let dir;

before(async () => {
  if (!hasOpenssl) return;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flawradar-tls-'));
  execFileSync(
    'openssl',
    ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '30',
      '-subj', '/CN=localhost', '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')],
    { stdio: 'ignore' },
  );
  server = https.createServer(
    { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')), minVersion: 'TLSv1.2' },
    (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/html',
        'Strict-Transport-Security': 'max-age=31536000',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end('<html><body>ok</body></html>');
    },
  );
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

after(() => {
  server?.close();
  server?.closeAllConnections?.();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

test('a self-signed HTTPS site is scanned and the certificate is reported as untrusted', { skip: !hasOpenssl && 'openssl not installed' }, async () => {
  const result = await runScan(parseTarget(`https://127.0.0.1:${port}`));
  const f = (id) => result.findings.find((x) => x.id === id);
  assert.equal(result.https, true);
  assert.equal(f('https').status, 'pass');
  assert.equal(f('tls-cert').status, 'fail');
  assert.match(f('tls-cert').detail, /self-signed/);
  assert.equal(f('hsts').status, 'pass');
  assert.equal(f('xcto').status, 'pass');
  assert.equal(f('tls-key').status, 'pass');
  // Server only speaks TLS 1.2+, so the legacy probe must not report acceptance.
  assert.notEqual(f('tls-protocol').status, 'fail');
  assert.equal(result.tls.protocol, 'TLSv1.3');
  assert.equal(result.grade, 'F'); // failed critical check caps the grade
});
