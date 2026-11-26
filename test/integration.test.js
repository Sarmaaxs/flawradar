import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

// Fixture servers live on 127.0.0.1, so development mode must be on.
process.env.FLAWRADAR_ALLOW_PRIVATE = '1';
process.env.FLAWRADAR_DB = ':memory:';
process.env.FLAWRADAR_QUIET = '1';
process.env.FLAWRADAR_SCANS_PER_HOUR = '500';
process.env.FLAWRADAR_SCANS_PER_HOST_PER_HOUR = '500';
process.env.FLAWRADAR_PUBLIC_IPS = '203.0.113.10,2001:db8::10';
process.env.FLAWRADAR_BASE_URL = 'https://radar.example';

const { createServer } = await import('../server/app.js');
const { config } = await import('../server/config.js');
const { parseTarget } = await import('../server/scanner/net.js');
const db = await import('../server/db.js');

let flawradar;
let flawradarUrl;
let weak;
let weakPort;
let proofValue = null;
let blocker;
let blockerPort;
let down;
let downPort;

const listen = (server) =>
  new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

before(async () => {
  // A badly configured site: no security headers, a loose session cookie,
  // reflected CORS, exposed .env and .git, and a directory listing.
  weak = http.createServer((req, res) => {
    const url = req.url.split('?')[0];
    if (req.method === 'OPTIONS') {
      res.writeHead(200, { Allow: 'GET, POST, TRACE, OPTIONS' });
      return res.end();
    }
    if (url === '/.well-known/flawradar-verify.txt') {
      if (!proofValue) {
        res.writeHead(404);
        return res.end('nope');
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(`${proofValue}\n`);
    }
    if (url === '/.env') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('DB_PASSWORD=hunter2\nAPI_KEY=abc123\n');
    }
    if (url === '/.git/HEAD') {
      res.writeHead(200);
      return res.end('ref: refs/heads/main\n');
    }
    if (url === '/uploads/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1></body></html>');
    }
    if (url === '/backup.sql' || url === '/phpinfo.php') {
      // Soft 404: answers 200 to anything. Must not count as exposure.
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<html><body>Sorry, page not found</body></html>');
    }
    if (url === '/') {
      const headers = {
        'Content-Type': 'text/html',
        Server: 'Apache/2.4.41 (Ubuntu)',
        'Set-Cookie': ['sessionid=abc123; Path=/'],
      };
      if (req.headers.origin) {
        headers['Access-Control-Allow-Origin'] = req.headers.origin;
        headers['Access-Control-Allow-Credentials'] = 'true';
      }
      res.writeHead(200, headers);
      return res.end('<html><body><form action="/login"><input type="password"></form></body></html>');
    }
    res.writeHead(404);
    res.end('not found');
  });
  weakPort = await listen(weak);

  // A firewall that blocks unknown scanners.
  blocker = http.createServer((req, res) => {
    res.writeHead(403, { 'Content-Type': 'text/html', Server: 'cloudflare', 'cf-ray': 'abc-LHR' });
    res.end('<html><body>Attention Required! | Cloudflare</body></html>');
  });
  blockerPort = await listen(blocker);

  // A port with nothing behind it.
  const probe = http.createServer();
  downPort = await listen(probe);
  await new Promise((r) => probe.close(r));

  flawradar = createServer();
  const port = await listen(flawradar);
  flawradarUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  for (const s of [flawradar, weak, blocker, down]) s?.close();
  flawradar?.closeAllConnections?.();
  weak?.closeAllConnections?.();
  db.close();
});

const json = async (path, options = {}) => {
  const res = await fetch(`${flawradarUrl}${path}`, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
  });
  const text = await res.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, headers: res.headers, body };
};

const post = (path, data) => json(path, { method: 'POST', body: JSON.stringify(data) });
const terms = config.termsVersion;

async function scan(url, deep = false) {
  const created = await post('/api/scans', { url, deep, terms });
  assert.equal(created.status, 202, JSON.stringify(created.body));
  for (let i = 0; i < 100; i += 1) {
    const { body } = await json(`/api/scans/${created.body.id}`);
    if (body.status !== 'queued' && body.status !== 'running') return body;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('scan did not finish');
}

const finding = (report, id) => report.result.findings.find((f) => f.id === id);

test('scanning a badly configured site finds the problems', async () => {
  const report = await scan(`http://127.0.0.1:${weakPort}`);
  assert.equal(report.status, 'done');
  assert.equal(report.result.https, false);
  assert.equal(report.result.grade, 'F');
  assert.equal(finding(report, 'https').status, 'fail');
  assert.equal(finding(report, 'csp').status, 'fail');
  assert.equal(finding(report, 'hsts').status, 'skip');
  assert.equal(finding(report, 'cookie-httponly').status, 'fail');
  assert.equal(finding(report, 'banner').status, 'warn');
  assert.equal(finding(report, 'cors').status, 'fail');
  assert.equal(finding(report, 'password-form').status, 'fail');
  assert.equal(finding(report, 'security-txt').status, 'warn');
  // Not verified, so the deep checks stay off.
  assert.equal(finding(report, 'exposed-env').status, 'skip');
  assert.equal(report.progress.every((s) => s.state === 'done'), true);
});

test('deep scans are refused until ownership is proved, then find exposed files', async () => {
  const host = `127.0.0.1`;
  const refused = await post('/api/scans', { url: `http://${host}:${weakPort}`, deep: true, terms });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error.code, 'needs_verification');
  assert.ok(refused.body.error.tried.length >= 1);

  const instructions = await post('/api/verify', { host: `http://${host}:${weakPort}` });
  assert.equal(instructions.status, 200);
  assert.match(instructions.body.value, /^flawradar-verify=[a-f0-9]{32}$/);
  // The token is stable for a host.
  const again = await post('/api/verify', { host: host });
  assert.equal(again.body.value, instructions.body.value);

  const wrong = await post('/api/verify/check', { host: `http://${host}:${weakPort}` });
  assert.equal(wrong.body.verified, false);

  proofValue = instructions.body.value;
  const right = await post('/api/verify/check', { host: `http://${host}:${weakPort}` });
  assert.equal(right.body.verified, true);
  assert.equal(right.body.method, 'file');

  const report = await scan(`http://${host}:${weakPort}`, true);
  assert.equal(report.deep, true);
  assert.equal(finding(report, 'exposed-env').status, 'fail');
  assert.match(finding(report, 'exposed-env').evidence, /\/\.env/);
  assert.equal(finding(report, 'exposed-vcs').status, 'fail');
  assert.equal(finding(report, 'dir-listing').status, 'fail');
  assert.equal(finding(report, 'http-methods').status, 'fail');
  // The soft-404 answers 200 but does not look like a dump or phpinfo.
  assert.equal(finding(report, 'exposed-backup').status, 'pass');
  assert.equal(finding(report, 'exposed-misc').status, 'pass');
  // The secret itself is never stored.
  assert.doesNotMatch(JSON.stringify(report), /hunter2/);

  // Taking the proof down withdraws permission.
  proofValue = null;
  const withdrawn = await post('/api/scans', { url: `http://${host}:${weakPort}`, deep: true, terms });
  assert.equal(withdrawn.status, 403);
});

test('fix download contains only the fixes that apply', async () => {
  const report = await scan(`http://127.0.0.1:${weakPort}`);
  const nginx = await json(`/api/scans/${report.id}/fix?server=nginx`);
  assert.equal(nginx.status, 200);
  assert.match(nginx.headers.get('content-disposition'), /flawradar-nginx\.conf/);
  assert.match(nginx.body, /add_header Content-Security-Policy/);
  assert.match(nginx.body, /server_tokens off;/);
  const express = await json(`/api/scans/${report.id}/fix?server=express`);
  assert.match(express.body, /res\.setHeader\("X-Content-Type-Options", "nosniff"\)/);
  assert.equal((await json(`/api/scans/${report.id}/fix?server=iis`)).status, 400);
});

test('a firewall block page is reported as blocked, not graded', async () => {
  const report = await scan(`http://127.0.0.1:${blockerPort}`);
  assert.equal(report.status, 'blocked');
  assert.equal(report.result.blocked.vendor, 'Cloudflare');
  assert.equal(report.result.score, null);
  assert.deepEqual(report.result.findings, []);
});

test('an unreachable host fails cleanly', async () => {
  const report = await scan(`http://127.0.0.1:${downPort}`);
  assert.equal(report.status, 'failed');
  assert.match(report.error, /Could not connect/);
});

test('later scans of a host show the previous result', async () => {
  const first = await scan(`http://127.0.0.1:${weakPort}`);
  const second = await scan(`http://127.0.0.1:${weakPort}`);
  assert.equal(second.previous.id, first.id);
});

test('api input handling', async () => {
  assert.equal((await post('/api/scans', {})).status, 400);
  assert.equal((await post('/api/scans', { url: 'ftp://x.example.com' })).status, 400);
  const notJson = await json('/api/scans', { method: 'POST', body: 'url=example.com', headers: { 'Content-Type': 'text/plain' } });
  assert.equal(notJson.status, 415);
  const badJson = await json('/api/scans', { method: 'POST', body: '{nope', headers: { 'Content-Type': 'application/json' } });
  assert.equal(badJson.status, 400);
  const big = await json('/api/scans', { method: 'POST', body: JSON.stringify({ url: 'a'.repeat(9000) }), headers: { 'Content-Type': 'application/json' } });
  assert.equal(big.status, 413);
  assert.equal((await json('/api/scans/' + 'a'.repeat(24))).status, 404);
  assert.equal((await json('/api/scans/not-an-id')).status, 404);
  const wrongMethod = await json('/api/scans', { method: 'GET' });
  assert.equal(wrongMethod.status, 405);
  assert.match(wrongMethod.headers.get('allow'), /POST/);
});

test('scanner details come from configuration', async () => {
  const { body } = await json('/api/scanner');
  assert.deepEqual(body.ips, ['203.0.113.10', '2001:db8::10']);
  assert.match(body.userAgent, /^FlawRadar-Scanner\/[\d.]+ \(\+.+\/whitelist\)$/);
});

test('pages and assets are served with security headers', async () => {
  for (const path of ['/', '/whitelist', '/verify', '/checks', '/about', '/assets/css/flawradar.css', '/assets/js/components.js', '/robots.txt']) {
    const res = await fetch(`${flawradarUrl}${path}`);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get('content-security-policy'), /default-src 'none'/, path);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff', path);
    assert.equal(res.headers.get('x-frame-options'), 'DENY', path);
  }
  const report = await fetch(`${flawradarUrl}/report/${'a'.repeat(24)}`);
  assert.equal(report.status, 200);
  assert.equal(report.headers.get('x-robots-tag'), 'noindex');
  assert.equal((await fetch(`${flawradarUrl}/nothing-here`)).status, 404);
});

test('static serving cannot escape the public directory', async () => {
  const net = await import('node:net');
  const port = new URL(flawradarUrl).port;
  const raw = (target) =>
    new Promise((resolve) => {
      const socket = net.connect(Number(port), '127.0.0.1', () => {
        socket.write(`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
      });
      let data = '';
      socket.on('data', (c) => { data += c; });
      socket.on('close', () => resolve(data));
    });
  for (const target of ['/assets/../../package.json', '/assets/%2e%2e/%2e%2e/package.json', '/assets/..%2f..%2fpackage.json', '/assets/%00']) {
    const response = await raw(target);
    assert.doesNotMatch(response, /"name": "flawradar"/, target);
    assert.match(response, /^HTTP\/1\.1 (400|404)/, target);
  }
});

test('the deep-scan page markup has no inline scripts or styles (CSP safe)', async () => {
  for (const path of ['/', '/whitelist', '/verify', '/checks', '/about', `/report/${'a'.repeat(24)}`]) {
    const html = await (await fetch(`${flawradarUrl}${path}`)).text();
    assert.doesNotMatch(html, /\sstyle=/i, path);
    assert.doesNotMatch(html, /\son[a-z]+=/i, path);
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)/i, path);
  }
});

test('parseTarget in development mode allows IPs and ports', () => {
  const t = parseTarget('http://127.0.0.1:8080');
  assert.equal(t.host, '127.0.0.1');
  assert.equal(t.port, 8080);
});
