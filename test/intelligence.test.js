import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseRobots, isDisallowed, extractLinks, sitemapLocations,
  fingerprint, extractApiEndpoints, extractFormInputs, cpeFor,
} from '../server/scanner/intelligence.js';
import { robotsDisallowRules, robotsDisallowsPath, sitemapPaths } from '../server/scanner/scan.js';
import { registrableDomain } from '../server/scanner/dnsinfo.js';

test('robots parser extracts wildcard rules and same-origin sitemap only', () => {
  const parsed = parseRobots([
    'User-agent: *',
    'Disallow: /admin',
    'Disallow: /private/',
    'Sitemap: https://example.com/sitemap.xml',
    'Sitemap: https://elsewhere.test/sitemap.xml',
    'User-agent: Googlebot',
    'Disallow: /google-only',
  ].join('\n'), 'https://example.com');
  assert.deepEqual(parsed.disallow, ['/admin', '/private/']);
  assert.deepEqual(parsed.sitemaps, ['https://example.com/sitemap.xml']);
  assert.equal(isDisallowed('/admin/login', parsed.disallow), true);
  assert.equal(isDisallowed('/public', parsed.disallow), false);
});

test('sitemap and page links stay on the same origin', () => {
  const urls = sitemapLocations('<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://evil.test/b</loc></url></urlset>', 'https://example.com');
  assert.deepEqual(urls, ['https://example.com/a']);
  assert.deepEqual(extractLinks('<a href="/docs">Docs</a><a href="https://evil.test">Other</a>', 'https://example.com/'), ['https://example.com/docs']);
});

test('technology fingerprint records evidence and exact version where available', () => {
  const tech = fingerprint('<meta name="generator" content="WordPress 6.4.2"><script src="/assets/jquery-3.6.0.min.js"></script>', { server: 'nginx/1.24.0' }, { scripts: [{ url: 'https://example.com/assets/jquery-3.6.0.min.js' }], styles: [], generator: 'WordPress 6.4.2' });
  assert.ok(tech.some((x) => x.name === 'nginx' && x.version === '1.24.0'));
  assert.ok(tech.some((x) => x.name === 'WordPress' && x.version === '6.4.2'));
  assert.ok(tech.some((x) => x.name === 'jQuery' && x.version === '3.6.0'));
});

test('API endpoint extraction keeps same-origin paths and parameter names, never values', () => {
  const found = extractApiEndpoints('fetch("/api/v1/users?token=do-not-copy"); axios.post("/graphql"); fetch("https://evil.test/api");', 'https://example.com/app.js');
  assert.equal(found.length, 2);
  assert.ok(found.some((x) => x.url === 'https://example.com/api/v1/users' && x.params.includes('token')));
  assert.ok(found.every((x) => !x.url.includes('do-not-copy')));
});

test('form inventory records names and method but strips query values', () => {
  const forms = extractFormInputs('<form action="/login?state=secret" method="post"><input name="username"><input name="password" type="password"></form>', 'https://example.com/');
  assert.equal(forms.length, 1);
  assert.equal(forms[0].action, 'https://example.com/login');
  assert.equal(forms[0].method, 'POST');
  assert.deepEqual(forms[0].fields, ['username', 'password']);
  assert.equal(forms[0].password, true);
});

test('CPE correlation requires a recognised product and an exact version', () => {
  assert.equal(cpeFor({ name: 'Apache', version: '2.4.49' }), 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*');
  assert.equal(cpeFor({ name: 'Apache', version: null }), null);
  assert.equal(cpeFor({ name: 'UnknownServer', version: '1.2.3' }), null);
});


test('baseline crawler respects robots disallow rules before fetching candidate pages', () => {
  const rules = robotsDisallowRules('User-agent: *\nDisallow: /admin\nDisallow: /private\nUser-agent: otherbot\nDisallow: /other');
  assert.equal(robotsDisallowsPath('/admin/login', rules), true);
  assert.equal(robotsDisallowsPath('/private/file', rules), true);
  assert.equal(robotsDisallowsPath('/public', rules), false);
});


test('baseline sitemap extraction stays on the exact host and obeys robots rules', () => {
  const paths = sitemapPaths('<urlset><url><loc>https://example.com/public</loc></url><url><loc>https://example.com/admin</loc></url><url><loc>https://other.example.com/child</loc></url></urlset>', 'https://example.com', ['/admin']);
  assert.deepEqual(paths, ['/public']);
});


test('registrable domain handles Ethiopian second-level domains', () => {
  assert.equal(registrableDomain('www.example.pro.et'), 'example.pro.et');
  assert.equal(registrableDomain('api.example.com.et'), 'example.com.et');
});
