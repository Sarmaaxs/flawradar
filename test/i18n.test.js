import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const dir = new URL('../public/assets/i18n/', import.meta.url);
const read = (f) => JSON.parse(readFileSync(new URL(f, dir), 'utf8'));
const index = read('index.json');
const codes = index.filter((l) => l.code !== 'en').map((l) => l.code);

test('every listed language has a file, and every file is listed', () => {
  const files = readdirSync(dir).filter((f) => f !== 'index.json').map((f) => f.replace('.json', '')).sort();
  assert.deepEqual(files, [...codes].sort());
});

test('every language translates exactly the same lines, with none left empty', () => {
  const base = Object.keys(read(`${codes[0]}.json`)).sort();
  for (const code of codes) {
    const dict = read(`${code}.json`);
    assert.deepEqual(Object.keys(dict).sort(), base, code);
    for (const [key, value] of Object.entries(dict)) assert.ok(typeof value === 'string' && value.trim(), `${code}: ${key}`);
  }
});

test('right-to-left languages are marked, and no translation contains markup', () => {
  assert.equal(index.find((l) => l.code === 'ar').dir, 'rtl');
  for (const code of codes) for (const value of Object.values(read(`${code}.json`))) assert.ok(!/[<>]/.test(value), `${code}: ${value}`);
});

test('matching ignores spacing and curly apostrophes', async () => {
  globalThis.document = { documentElement: {} };
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  const { normalise } = await import('../public/assets/js/i18n.js');
  assert.equal(normalise("  Check your\n   website’s   security "), "Check your website's security");
});
