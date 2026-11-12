import test from 'node:test';
import assert from 'node:assert/strict';

const { evaluate, parseCsp, PROBE_ORIGIN, CHECKS } = await import('../server/scanner/checks.js');
const { summarize } = await import('../server/scanner/score.js');
const { buildFixConfig } = await import('../server/scanner/fixes.js');
const { extractResources } = await import('../server/scanner/html.js');
const { registrableDomain } = await import('../server/scanner/dnsinfo.js');

const goodHeaders = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  server: 'nginx',
};

function ctx(overrides = {}) {
  const { headers, body, https = true, ...rest } = overrides;
  return {
    host: 'example.com',
    page: {
      https,
      res: {
        status: 200,
        url: https ? 'https://example.com/' : 'http://example.com/',
        headers: { 'content-type': 'text/html', ...goodHeaders, ...headers },
        body: body ?? '<html><body>hi</body></html>',
      },
    },
    http: { res: { status: 301, headers: { location: 'https://example.com/' } } },
    tls: {
      ok: true,
      authorized: true,
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384' },
      legacy: { tls10: false, tls11: false },
      cert: {
        subject: 'CN=example.com',
        issuer: 'CN=Test CA',
        validTo: new Date(Date.now() + 90 * 86_400_000).toISOString(),
        keyType: 'ec',
        keyBits: null,
        curve: 'prime256v1',
      },
    },
    cors: { res: { headers: {} } },
    dns: {
      apex: 'example.com',
      mx: ['mail.example.com'],
      spf: ['v=spf1 include:_spf.mail.example ~all'],
      dmarc: ['v=DMARC1; p=reject'],
      caa: ['letsencrypt.org'],
    },
    securityTxt: { found: true, path: '/.well-known/security.txt', expires: new Date(Date.now() + 90 * 86_400_000).toISOString() },
    deep: null,
    ...rest,
  };
}

const status = (results, id) => results.find((r) => r.id === id).status;

test('a well configured site has no failures or warnings', () => {
  const results = evaluate(ctx());
  const notGood = results.filter((r) => r.status === 'fail' || r.status === 'warn');
  assert.deepEqual(notGood.map((r) => `${r.id}: ${r.detail}`), []);
  const s = summarize(results);
  assert.equal(s.score, 100);
  assert.equal(s.grade, 'A');
});

test('every check has a unique id and explanation', () => {
  const ids = CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of CHECKS) {
    assert.ok(c.title && c.why && c.ref && c.severity, c.id);
  }
});

test('missing headers fail with fix snippets', () => {
  const results = evaluate(ctx({ headers: { 'strict-transport-security': undefined, 'content-security-policy': undefined, 'x-content-type-options': undefined } }));
  for (const id of ['hsts', 'csp', 'xcto']) {
    const r = results.find((x) => x.id === id);
    assert.equal(r.status, 'fail', id);
    assert.ok(r.fix.snippets.nginx.includes('add_header'), id);
    assert.ok(r.fix.snippets.apache.includes('Header always set'), id);
  }
});

test('HSTS: short max-age warns, zero fails', () => {
  assert.equal(status(evaluate(ctx({ headers: { 'strict-transport-security': 'max-age=3600' } })), 'hsts'), 'warn');
  assert.equal(status(evaluate(ctx({ headers: { 'strict-transport-security': 'max-age=0' } })), 'hsts'), 'fail');
  assert.equal(status(evaluate(ctx({ headers: { 'strict-transport-security': 'includeSubDomains' } })), 'hsts'), 'fail');
});

test('CSP: unsafe-inline, wildcards and report-only are flagged', () => {
  const run = (value, name = 'content-security-policy') => status(evaluate(ctx({ headers: { 'content-security-policy': undefined, [name]: value } })), 'csp');
  assert.equal(run("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"), 'warn');
  assert.equal(run("script-src 'self' 'unsafe-eval'; object-src 'none'"), 'warn');
  assert.equal(run('script-src *; object-src none'), 'warn');
  assert.equal(run("img-src 'self'"), 'warn');
  assert.equal(run("default-src 'self'", 'content-security-policy-report-only'), 'warn');
  assert.equal(run("script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'"), 'pass');
});

test('parseCsp keeps the first occurrence of a directive', () => {
  const d = parseCsp("default-src 'self'; script-src a b; script-src c");
  assert.deepEqual(d['script-src'], ['a', 'b']);
});

test('framing accepts X-Frame-Options or frame-ancestors', () => {
  const none = { 'content-security-policy': undefined, 'x-frame-options': undefined };
  assert.equal(status(evaluate(ctx({ headers: none })), 'framing'), 'fail');
  assert.equal(status(evaluate(ctx({ headers: { ...none, 'x-frame-options': 'DENY' } })), 'framing'), 'pass');
  assert.equal(status(evaluate(ctx({ headers: { ...none, 'x-frame-options': 'ALLOW-FROM https://a.example' } })), 'framing'), 'warn');
});

test('cookies: session cookie without flags fails, other cookies warn', () => {
  const sess = evaluate(ctx({ headers: { 'set-cookie': ['sessionid=abc; Path=/'] } }));
  assert.equal(status(sess, 'cookie-secure'), 'fail');
  assert.equal(status(sess, 'cookie-httponly'), 'fail');
  assert.equal(status(sess, 'cookie-samesite'), 'warn');
  const other = evaluate(ctx({ headers: { 'set-cookie': ['theme=dark; Path=/'] } }));
  assert.equal(status(other, 'cookie-secure'), 'warn');
  const good = evaluate(ctx({ headers: { 'set-cookie': ['sid=abc; Secure; HttpOnly; SameSite=Lax'] } }));
  for (const id of ['cookie-secure', 'cookie-httponly', 'cookie-samesite']) assert.equal(status(good, id), 'pass', id);
  const none = evaluate(ctx({ headers: { 'set-cookie': ['x=1; SameSite=None'] } }));
  assert.equal(status(none, 'cookie-samesite'), 'fail');
});

test('TLS: expiry windows, untrusted certificates and legacy protocols', () => {
  const withDays = (days) => {
    const c = ctx();
    c.tls.cert.validTo = new Date(Date.now() + days * 86_400_000).toISOString();
    return status(evaluate(c), 'tls-cert');
  };
  assert.equal(withDays(60), 'pass');
  assert.equal(withDays(20), 'warn');
  assert.equal(withDays(5), 'fail');
  assert.equal(withDays(-3), 'fail');

  const selfSigned = ctx();
  selfSigned.tls.authorized = false;
  selfSigned.tls.authError = 'DEPTH_ZERO_SELF_SIGNED_CERT';
  const r = evaluate(selfSigned).find((x) => x.id === 'tls-cert');
  assert.equal(r.status, 'fail');
  assert.match(r.detail, /self-signed/);

  const old = ctx();
  old.tls.legacy.tls10 = true;
  assert.equal(status(evaluate(old), 'tls-protocol'), 'fail');

  const weak = ctx();
  weak.tls.cert.keyType = 'rsa';
  weak.tls.cert.keyBits = 1024;
  assert.equal(status(evaluate(weak), 'tls-key'), 'fail');
});

test('plain HTTP site fails the transport checks', () => {
  const c = ctx({ https: false, tls: null, headers: { 'strict-transport-security': undefined } });
  c.page.httpsError = 'ECONNREFUSED';
  const results = evaluate(c);
  assert.equal(status(results, 'https'), 'fail');
  assert.equal(status(results, 'hsts'), 'skip');
  assert.equal(status(results, 'tls-cert'), 'skip');
});

test('http-redirect: missing redirect fails, temporary redirect still passes with a note', () => {
  const c = ctx();
  c.http = { res: { status: 200, headers: {} } };
  assert.equal(status(evaluate(c), 'http-redirect'), 'fail');
  const temp = ctx();
  temp.http = { res: { status: 302, headers: { location: 'https://example.com/' } } };
  const r = evaluate(temp).find((x) => x.id === 'http-redirect');
  assert.equal(r.status, 'pass');
  assert.match(r.detail, /temporary/);
  const toHttp = ctx();
  toHttp.http = { res: { status: 301, headers: { location: 'http://example.com/other' } } };
  assert.equal(status(evaluate(toHttp), 'http-redirect'), 'fail');
});

test('CORS: reflected origin with credentials fails', () => {
  const c = ctx();
  c.cors = { res: { headers: { 'access-control-allow-origin': PROBE_ORIGIN, 'access-control-allow-credentials': 'true' } } };
  assert.equal(status(evaluate(c), 'cors'), 'fail');
  c.cors = { res: { headers: { 'access-control-allow-origin': PROBE_ORIGIN } } };
  assert.equal(status(evaluate(c), 'cors'), 'warn');
  c.cors = { res: { headers: { 'access-control-allow-origin': 'https://app.example.com' } } };
  assert.equal(status(evaluate(c), 'cors'), 'pass');
});

test('banner: version numbers are flagged, bare names are not', () => {
  assert.equal(status(evaluate(ctx({ headers: { server: 'Apache/2.4.41 (Ubuntu)' } })), 'banner'), 'warn');
  assert.equal(status(evaluate(ctx({ headers: { 'x-powered-by': 'PHP/7.4' } })), 'banner'), 'warn');
  assert.equal(status(evaluate(ctx({ headers: { server: 'nginx' } })), 'banner'), 'pass');
});

test('mixed content and password forms', () => {
  const html = '<script src="http://cdn.example.net/a.js"></script><img src="http://x.example/i.png">';
  assert.equal(status(evaluate(ctx({ body: html })), 'mixed-content'), 'fail');
  assert.equal(status(evaluate(ctx({ body: '<img src="http://x.example/i.png">' })), 'mixed-content'), 'warn');
  const form = '<form action="http://example.com/login"><input type="password" name="p"></form>';
  assert.equal(status(evaluate(ctx({ body: form })), 'password-form'), 'fail');
  const safe = '<form action="/login"><input type="password" name="p"></form>';
  assert.equal(status(evaluate(ctx({ body: safe })), 'password-form'), 'pass');
});

test('sri: third-party scripts without integrity warn', () => {
  const html = '<script src="https://cdn.example.net/a.js"></script><script src="/own.js"></script>';
  assert.equal(status(evaluate(ctx({ body: html })), 'sri'), 'warn');
  const ok = '<script src="https://cdn.example.net/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>';
  assert.equal(status(evaluate(ctx({ body: ok })), 'sri'), 'pass');
});

test('mail: SPF and DMARC edge cases', () => {
  const run = (dns) => evaluate(ctx({ dns: { apex: 'example.com', mx: ['m.example.com'], spf: [], dmarc: [], caa: [], ...dns } }));
  assert.equal(status(run({}), 'spf'), 'fail');
  assert.equal(status(run({ spf: ['v=spf1 +all'] }), 'spf'), 'fail');
  assert.equal(status(run({ spf: ['v=spf1 a ?all'] }), 'spf'), 'warn');
  assert.equal(status(run({ spf: ['v=spf1 a -all'] }), 'spf'), 'pass');
  assert.equal(status(run({ spf: ['v=spf1 a -all', 'v=spf1 mx -all'] }), 'spf'), 'fail');
  assert.equal(status(run({}), 'dmarc'), 'fail');
  assert.equal(status(run({ dmarc: ['v=DMARC1; p=none'] }), 'dmarc'), 'warn');
  assert.equal(status(run({ dmarc: ['v=DMARC1; p=quarantine'] }), 'dmarc'), 'pass');
  // A domain that sends no mail is not failed for lacking mail records.
  const noMail = evaluate(ctx({ dns: { apex: 'example.com', mx: [], spf: [], dmarc: [], caa: [] } }));
  assert.equal(status(noMail, 'spf'), 'info');
  assert.equal(status(noMail, 'dmarc'), 'info');
  // A failed lookup is skipped, not reported as missing.
  assert.equal(status(evaluate(ctx({ dns: { apex: 'example.com', mx: null, spf: null, dmarc: null, caa: null } })), 'spf'), 'skip');
});

test('deep checks are skipped without ownership proof and report hits with it', () => {
  assert.equal(status(evaluate(ctx()), 'exposed-env'), 'skip');
  const deep = { hits: [{ group: 'env', path: '/.env', status: 200 }], listings: ['/uploads/'], allow: ['GET', 'TRACE'] };
  const results = evaluate(ctx({ deep }));
  assert.equal(status(results, 'exposed-env'), 'fail');
  assert.equal(status(results, 'exposed-vcs'), 'pass');
  assert.equal(status(results, 'dir-listing'), 'fail');
  assert.equal(status(results, 'http-methods'), 'fail');
});

test('scoring and grade caps', () => {
  const f = (severity, st) => ({ severity, status: st });
  assert.deepEqual(summarize([f('low', 'pass')]).grade, 'A');
  // One failed critical check caps at F even if the score alone would be higher.
  const crit = summarize([f('critical', 'fail'), ...Array(10).fill(f('low', 'pass'))]);
  assert.equal(crit.score, 70);
  assert.equal(crit.grade, 'F');
  // One failed high check caps at C.
  const high = summarize([f('high', 'fail')]);
  assert.equal(high.score, 85);
  assert.equal(high.grade, 'C');
  // Warnings cost half and never cap.
  const warn = summarize([f('high', 'warn'), f('medium', 'warn')]);
  assert.equal(warn.score, 89);
  assert.equal(warn.grade, 'B');
  // Skips and info cost nothing.
  assert.equal(summarize([f('critical', 'skip'), f('critical', 'info')]).score, 100);
  assert.equal(summarize([]).grade, 'A');
});

test('fix config bundles only failing checks for the chosen server', () => {
  const results = evaluate(ctx({ headers: { 'x-content-type-options': undefined, 'referrer-policy': undefined } }));
  const nginx = buildFixConfig(results, 'nginx', 'example.com');
  assert.match(nginx, /add_header X-Content-Type-Options "nosniff" always;/);
  assert.match(nginx, /add_header Referrer-Policy/);
  assert.doesNotMatch(nginx, /Strict-Transport-Security/);
  const express = buildFixConfig(results, 'express', 'example.com');
  assert.match(express, /app\.use\(\(req, res, next\) => \{/);
  assert.match(express, /next\(\);/);
  assert.equal(buildFixConfig(evaluate(ctx()), 'nginx', 'example.com'), null);
  assert.equal(buildFixConfig(results, 'iis', 'example.com'), null);
});

test('html extraction finds resources, ignores comments', () => {
  const r = extractResources(
    '<!-- <script src="http://hidden.example/x.js"></script> --><script src=/a.js></script><link rel="stylesheet" href="https://c.example/s.css" integrity="sha384-x"><form action="/go"><input type=password></form><meta name="generator" content="WordPress 6.0">',
    'https://example.com/page',
  );
  assert.deepEqual(r.scripts.map((s) => s.url), ['https://example.com/a.js']);
  assert.equal(r.styles[0].integrity, 'sha384-x');
  assert.equal(r.forms[0].hasPassword, true);
  assert.equal(r.generator, 'WordPress 6.0');
});

test('registrableDomain handles common two-part endings', () => {
  assert.equal(registrableDomain('www.example.com'), 'example.com');
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.com'), 'example.com');
});
