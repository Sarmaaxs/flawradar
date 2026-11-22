import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

process.env.FLAWRADAR_DB = ':memory:';
process.env.FLAWRADAR_QUIET = '1';
delete process.env.FLAWRADAR_BASE_URL;

const { config, userAgent, isLocalUrl } = await import('../server/config.js');
const db = await import('../server/db.js');

test('a local development address never reaches site owners or visitors', () => {
  assert.ok(isLocalUrl('http://localhost:3000') && isLocalUrl('http://127.0.0.1:3000') && !isLocalUrl('https://flawradar.pro.et'));
  assert.doesNotMatch(userAgent(), /localhost|127\.0\.0\.1/);
  config.baseUrl = 'https://flawradar.pro.et';
  assert.match(userAgent(), /\(\+https:\/\/flawradar\.pro\.et\/whitelist\)/);
  db.close();
});

test('pages written for visitors do not talk to the person running the site', () => {
  const root = path.join(import.meta.dirname, '..', 'public');
  const files = [];
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : files.push(path.join(d, e.name))));
  walk(root);
  // The Whitelist page legitimately shows nginx and fail2ban rules and the Checks page lists what the scanner looks for.
  const skip = /whitelist\.js$|checks\.|favicon/;
  for (const f of files.filter((x) => /\.(html|js)$/.test(x) && !skip.test(x))) {
    const text = fs.readFileSync(f, 'utf8');
    assert.doesNotMatch(text, /FLAWRADAR_[A-Z_]+/, `${f} names an environment variable`);
    assert.doesNotMatch(text, /localhost:\d+/, `${f} shows a local address`);
    assert.doesNotMatch(text, /this (FlawRadar )?instance|the person who runs/i, `${f} talks to the operator`);
  }
});
