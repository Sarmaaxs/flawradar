import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffScans } from '../server/scanner/diff.js';

const f = (id, status, severity = 'medium') => ({ id, title: id, status, severity });
const scan = (score, grade, findings) => ({ score, grade, findings });

test('fixed, new, worse and better are told apart', () => {
  const prev = scan(60, 'D', [f('a', 'fail'), f('b', 'pass'), f('c', 'warn'), f('d', 'fail'), f('e', 'pass')]);
  const curr = scan(74, 'C', [f('a', 'pass'), f('b', 'fail'), f('c', 'fail'), f('d', 'warn'), f('e', 'pass')]);
  const d = diffScans(prev, curr);
  assert.equal(d.scoreDelta, 14);
  assert.deepEqual([d.gradeFrom, d.gradeTo], ['D', 'C']);
  assert.deepEqual(d.fixed.map((x) => x.id), ['a']);
  assert.deepEqual(d.newProblems.map((x) => x.id), ['b']);
  assert.deepEqual(d.worse.map((x) => x.id), ['c']);
  assert.deepEqual(d.better.map((x) => x.id), ['d']);
  assert.equal(d.unchanged, 1);
});

test('a deep scan after a basic one does not report the deep checks as new problems', () => {
  const prev = scan(80, 'B', [f('a', 'pass'), f('exposed-env', 'skip')]);
  const curr = scan(70, 'C', [f('a', 'pass'), f('exposed-env', 'fail')]);
  const d = diffScans(prev, curr);
  assert.deepEqual(d.newProblems, []);
  assert.deepEqual(d.newlyChecked.map((x) => x.id), ['exposed-env']);
});

test('missing or damaged data gives no comparison instead of an error', () => {
  assert.equal(diffScans(null, scan(1, 'A', [])), null);
  assert.equal(diffScans({ findings: 'x' }, scan(1, 'A', [])), null);
});
