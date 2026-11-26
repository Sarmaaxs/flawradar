import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

// A fake mail server collects what would be sent, and a fixture site serves the ownership proof.
const mails = [];
const smtp = net.createServer((sock) => {
  sock.setEncoding('utf8');
  let data = '';
  let buf = '';
  const w = (s) => sock.write(`${s}\r\n`);
  w('220 fake');
  sock.on('data', (chunk) => {
    buf += chunk;
    for (;;) {
      if (data !== null && sock.inData) {
        const end = buf.indexOf('\r\n.\r\n');
        if (end < 0) return;
        mails.push(buf.slice(0, end));
        buf = buf.slice(end + 5);
        sock.inData = false;
        w('250 queued');
        continue;
      }
      const eol = buf.indexOf('\r\n');
      if (eol < 0) return;
      const line = buf.slice(0, eol);
      buf = buf.slice(eol + 2);
      if (/^EHLO/.test(line)) w('250 ok');
      else if (/^(MAIL|RCPT)/.test(line)) w('250 ok');
      else if (line === 'DATA') { sock.inData = true; w('354 go'); }
      else if (line === 'QUIT') { w('221 bye'); sock.end(); }
      else w('500 what');
    }
  });
});
await new Promise((r) => smtp.listen(0, '127.0.0.1', r));

process.env.FLAWRADAR_ALLOW_PRIVATE = '1';
process.env.FLAWRADAR_DB = ':memory:';
process.env.FLAWRADAR_QUIET = '1';
process.env.FLAWRADAR_SCANS_PER_HOUR = '500';
process.env.FLAWRADAR_SCANS_PER_HOST_PER_HOUR = '500';
process.env.FLAWRADAR_WATCH_SIGNUPS_PER_HOUR = '500';
process.env.FLAWRADAR_BASE_URL = 'https://radar.example';
process.env.FLAWRADAR_SMTP_HOST = '127.0.0.1';
process.env.FLAWRADAR_SMTP_PORT = String(smtp.address().port);
process.env.FLAWRADAR_SMTP_SECURE = 'none';
process.env.FLAWRADAR_SMTP_FROM = 'alerts@radar.example';

const { createServer } = await import('../server/app.js');
const { config } = await import('../server/config.js');
const db = await import('../server/db.js');
const { runDue, afterScan, gradeWorse } = await import('../server/watch.js');
const { instructions } = await import('../server/verify.js');
const { parseTarget } = await import('../server/scanner/net.js');
const { sendMail } = await import('../server/mail.js');
const { runBackup } = await import('../server/backup.js');
const { preflight } = await import('../server/preflight.js');
const TERMS = config.termsVersion;

let app, base, site, sitePort, proof;
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(s.address().port)));

before(async () => {
  site = http.createServer((req, res) => {
    if (req.url.startsWith('/.well-known/flawradar-verify.txt') && proof) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(proof);
    }
    if (req.url.startsWith('/.well-known/')) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><head><title>x</title></head><body>hi</body></html>');
  });
  sitePort = await listen(site);
  app = createServer();
  base = `http://127.0.0.1:${await listen(app)}`;
});

after(async () => {
  await new Promise((r) => setTimeout(r, 1500)); // let scans that are still running finish before the database closes
  for (const s of [app, site, smtp]) { s.close(); s.closeAllConnections?.(); }
  db.close();
});

const call = async (p, method, data, headers = {}) => {
  const res = await fetch(`${base}${p}`, { method, headers: { ...(data ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: data ? JSON.stringify(data) : undefined });
  const text = await res.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body, headers: res.headers };
};
const post = (p, d, h) => call(p, 'POST', d, h);
const SITE = () => `http://127.0.0.1:${sitePort}`;
const linkIn = (mail, part) => new URL(mail.match(new RegExp(`https://radar\\.example${part}\\?[^\\s]+`))[0]);

test('mail: sends a message through SMTP and strips header injection', async () => {
  mails.length = 0;
  await sendMail({ to: 'a@b.co', subject: 'Hi\r\nBcc: evil@x.co', text: 'line\n.dot line' });
  assert.equal(mails.length, 1);
  assert.match(mails[0], /Subject: Hi Bcc: evil@x\.co/);
  assert.ok(!/^Bcc:/m.test(mails[0]));
  assert.match(mails[0], /\.\.dot line/); // dot-stuffed
  await assert.rejects(sendMail({ to: 'not-an-address', subject: 's', text: 't' }));
});

test('a watch needs the terms, a valid address and proof of ownership', async () => {
  const body = { url: SITE(), email: 'me@example.org', terms: TERMS };
  assert.equal((await post('/api/watch', { ...body, terms: 'old' })).status, 400);
  assert.equal((await post('/api/watch', { ...body, email: 'nope' })).status, 400);
  const refused = await post('/api/watch', body);
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error.code, 'needs_verification');
});

test('sign-up, confirmation by link, a baseline, then an alert when the grade drops', async () => {
  proof = instructions(parseTarget(SITE())).value;
  mails.length = 0;
  const ok = await post('/api/watch', { url: SITE(), email: 'Me@Example.org', terms: TERMS });
  assert.equal(ok.status, 202, JSON.stringify(ok.body));
  assert.equal(mails.length, 1);
  assert.match(mails[0], /Confirm: FlawRadar watch/);
  const confirmUrl = linkIn(mails[0], '/watch/confirm');
  const id = confirmUrl.searchParams.get('id');
  const secret = confirmUrl.searchParams.get('s');

  // Not due and not confirmed: nothing runs.
  assert.equal(await runDue(), 0);
  assert.equal((await post('/api/watch/confirm', { id, s: 'wrong' })).status, 404);
  assert.equal((await post('/api/watch/confirm', { id, s: secret })).status, 200);

  // The page the email links to is served without a query-string leak into logs or caches.
  const page = await fetch(`${base}/watch/confirm?id=${id}&s=${secret}`);
  assert.equal(page.status, 200);

  // First run sets the baseline and sends nothing.
  mails.length = 0;
  assert.equal(await runDue(), 1);
  await waitFor(() => db.getWatch(id).last_grade);
  assert.equal(mails.length, 0);
  const baseline = db.getWatch(id);
  assert.ok(baseline.last_grade);

  // Pretend the last scan was much better: the next result counts as a drop.
  db.watchRan(id, { scanId: baseline.last_scan_id, score: 100, grade: 'A' });
  const w = db.getWatch(id);
  const scanId = baseline.last_scan_id;
  const outcome = await afterScan(w, scanId);
  assert.equal(outcome, baseline.last_grade === 'A' ? 'ok' : 'alerted');
  if (outcome === 'alerted') {
    assert.match(mails.at(-1), /Subject: 127\.0\.0\.1: grade A to /);
    assert.match(mails.at(-1), /\/report\//);
    assert.match(mails.at(-1), /\/watch\/stop\?id=/);
  }

  // Stopping deletes the record.
  assert.equal((await post('/api/watch/stop', { id, s: 'wrong' })).status, 404);
  assert.equal((await post('/api/watch/stop', { id, s: secret })).status, 200);
  assert.equal(db.getWatch(id), undefined);
});

test('removing the ownership proof pauses the watch and tells the owner', async () => {
  proof = instructions(parseTarget(SITE())).value;
  mails.length = 0;
  await post('/api/watch', { url: SITE(), email: 'pause@example.org', terms: TERMS });
  const u = linkIn(mails[0], '/watch/confirm');
  await post('/api/watch/confirm', { id: u.searchParams.get('id'), s: u.searchParams.get('s') });
  proof = null;
  mails.length = 0;
  assert.equal(await runDue(), 0);
  assert.match(mails.at(-1), /paused/);
  assert.equal(db.getWatch(u.searchParams.get('id')).paused, 'proof removed');
});

test('limits: one address can watch only so many sites; grades compare correctly', () => {
  assert.ok(gradeWorse('C', 'B') && !gradeWorse('A', 'A') && !gradeWorse('A', 'C'));
  assert.ok(config.maxWatchesPerEmail >= 1);
});

test('delete: only the browser that started the scan can delete the report', async () => {
  const made = await post('/api/scans', { url: SITE(), terms: TERMS });
  assert.equal(made.status, 202);
  assert.match(made.body.deleteToken, /^[a-f0-9]{48}$/);
  const id = made.body.id;
  assert.equal((await call(`/api/scans/${id}`, 'DELETE')).status, 403);
  assert.equal((await call(`/api/scans/${id}`, 'DELETE', null, { 'X-FlawRadar-Delete': 'f'.repeat(48) })).status, 403);
  // The token and its hash are never in the report itself.
  const read = await call(`/api/scans/${id}`, 'GET');
  assert.doesNotMatch(JSON.stringify(read.body), new RegExp(made.body.deleteToken));
  assert.doesNotMatch(JSON.stringify(read.body), /delete_hash|deleteHash/);
  const gone = await call(`/api/scans/${id}`, 'DELETE', null, { 'X-FlawRadar-Delete': made.body.deleteToken });
  assert.equal(gone.status, 200);
  assert.equal((await call(`/api/scans/${id}`, 'GET')).status, 404);
  assert.equal((await call(`/api/scans/${id}`, 'DELETE', null, { 'X-FlawRadar-Delete': made.body.deleteToken })).status, 404);
});

test('health answers for monitors, backups keep only the newest copies', async () => {
  const h = await call('/api/health', 'GET');
  assert.equal(h.status, 200);
  assert.deepEqual(Object.keys(h.body), ['ok']);
  assert.equal(h.body.ok, true);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flawradar-bk-'));
  for (let i = 0; i < 4; i += 1) runBackup({ dir, keep: 2, now: new Date(Date.UTC(2026, 10, 20 + i, 3, 0, 0)) });
  const files = fs.readdirSync(dir).sort();
  assert.equal(files.length, 2);
  assert.match(files[1], /^flawradar-20261123-030000\.db$/);
  assert.ok(fs.statSync(path.join(dir, files[1])).size > 0);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(runBackup({ dir: '' }), null);
});

test('preflight flags placeholders and private addresses', () => {
  const bad = preflight({ ...config, publicIps: ['203.0.113.10', '10.0.0.5', 'nope'], contact: '', legal: { entity: '' }, backup: { dir: '' } });
  const text = bad.map((i) => i.message).join('\n');
  assert.match(text, /documentation address/);
  assert.match(text, /private address/);
  assert.match(text, /not an IP address/);
  assert.match(text, /Legal details missing/);
  const empty = preflight({ ...config, publicIps: [] });
  assert.ok(empty.some((i) => i.level === 'error' && /PUBLIC_IPS is empty/.test(i.message)));
});

async function waitFor(fn, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('timed out');
}
