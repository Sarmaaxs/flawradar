import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// motion.js touches the DOM when it loads, so give it just enough of one.
let reducedMotion = false;
const classes = new Set();
globalThis.matchMedia = () => ({ get matches() { return reducedMotion; }, addEventListener() {} });
globalThis.document = { documentElement: { classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c) } }, querySelectorAll: () => [], readyState: 'loading', addEventListener() {} };
globalThis.sessionStorage = { getItem: () => null, setItem() {} };
globalThis.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };

const { countUp, stagger, crossfade, reduced } = await import('../public/assets/js/motion.js');

test('countUp jumps straight to the value when reduced motion is on', () => {
  reducedMotion = true;
  const seen = [];
  countUp((n) => seen.push(n), 87);
  assert.deepEqual(seen, [87]);
  assert.equal(reduced(), true);
  reducedMotion = false;
});

test('countUp does not animate a zero', () => {
  const seen = [];
  countUp((n) => seen.push(n), 0);
  assert.deepEqual(seen, [0]);
});

test('stagger numbers elements and caps the delay', () => {
  const els = Array.from({ length: 5 }, () => ({ style: { props: {}, setProperty(k, v) { this.props[k] = v; } } }));
  stagger(els, 3);
  assert.deepEqual(els.map((e) => e.style.props['--i']), ['0', '1', '2', '3', '3']);
});

test('crossfade runs the change at once when reduced motion is on', () => {
  reducedMotion = true;
  let ran = false;
  crossfade({ classList: { add() {}, remove() {} } }, () => { ran = true; });
  assert.equal(ran, true);
  reducedMotion = false;
});

test('the stylesheet defines the motion tokens and gates all movement', () => {
  const css = readFileSync(new URL('../public/assets/css/flawradar.css', import.meta.url), 'utf8');
  for (const t of ['--d-fast: 120ms', '--d-base: 240ms', '--d-slow: 420ms', '--d-slower: 700ms', '--ease-standard', '--ease-decel', '--ease-emph']) assert.ok(css.includes(t), t);
  assert.ok(css.includes('prefers-reduced-motion: no-preference'));
  assert.ok(css.includes('@view-transition'));
  const after = css.slice(css.indexOf('/* ---- Motion.'));
  assert.ok(!/outline\s*:\s*(none|0)\b/.test(css), 'the focus ring is never removed');
  assert.ok(!/(?:^|[;{\s])(?:width|height|top|left|margin[a-z-]*)\s*:[^;]*var\(--(?:p|fill)/.test(after.replace(/\.meter[^}]*}/g, '')), 'no layout properties animated');
});
