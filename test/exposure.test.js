import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessRisk, levelFor } from '../server/scanner/exposure.js';

const f = (id, status, severity = 'medium') => ({ id, title: id, status, severity });

test('a clean result carries no modelled risk', () => {
  const r = assessRisk([f('csp', 'pass'), f('hsts', 'pass', 'high'), f('x', 'info', 'low')]);
  assert.equal(r.percent, 0);
  assert.equal(r.level, 'Low');
  assert.deepEqual(r.ranked, []);
});

test('weaknesses combine as 1 minus the product of the chances left over', () => {
  // critical .45 and high .22: 1 - (.55 * .78) = .571
  const r = assessRisk([f('a', 'fail', 'critical'), f('b', 'fail', 'high')]);
  assert.equal(r.percent, 57.1);
  assert.equal(r.level, 'High');
});

test('a warning counts for less than a failure of the same severity', () => {
  assert.ok(assessRisk([f('a', 'warn', 'high')]).percent < assessRisk([f('a', 'fail', 'high')]).percent);
  assert.equal(assessRisk([f('a', 'warn', 'high')]).percent, 8.8);
});

test('weaknesses that are worse together add a combination term', () => {
  const alone = assessRisk([f('csp', 'fail', 'high')]).percent;
  const both = assessRisk([f('csp', 'fail', 'high'), f('cookie-httponly', 'fail', 'medium')]);
  assert.ok(both.chains.some((c) => c.id === 'cookie-theft'));
  const noChain = 1 - (1 - 0.22) * (1 - 0.09);
  assert.ok(both.probability > noChain, 'the combination raises the total');
  assert.ok(both.percent > alone);
});

test('fixes are ranked by how far they lower the total, and removing one breaks its chains', () => {
  const r = assessRisk([f('csp', 'fail', 'high'), f('cookie-httponly', 'fail', 'medium'), f('referrer', 'warn', 'low')]);
  assert.equal(r.ranked[0].id, 'csp');
  assert.ok(r.ranked[0].reduction > r.ranked[1].reduction);
  assert.ok(r.ranked[0].after < r.percent);
  // the CSP fix removes its own term and the chain, so it drops by more than its base 22 points
  assert.ok(r.ranked[0].reduction > 22);
});

test('levels', () => {
  assert.deepEqual([0.01, 0.1, 0.2, 0.5, 0.8].map(levelFor), ['Low', 'Guarded', 'Elevated', 'High', 'Severe']);
});
