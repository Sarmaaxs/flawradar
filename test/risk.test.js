import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRiskPriority } from '../server/scanner/risk.js';

test('risk priority weights CVSS, EPSS, KEV and public exposure transparently', () => {
  const result = calculateRiskPriority({ cvssBaseScore: 10, epss: { score: 1 }, kev: { dateAdded: '2026-01-01' }, confidence: 'high' });
  assert.equal(result.score, 100);
  assert.equal(result.band, 'critical');
  assert.deepEqual(result.components.map((item) => item.name), ['cvss', 'epss', 'knownExploited', 'publicExposure']);
});

test('risk priority renormalises weights when intelligence feeds are missing', () => {
  const result = calculateRiskPriority({ cvssBaseScore: 7.5, epss: null, kev: null, confidence: 'medium' });
  assert.equal(result.score, 68);
  assert.equal(result.components.length, 2);
});

test('risk priority refuses to invent a score when no severity signals exist', () => {
  const result = calculateRiskPriority({ confidence: 'low' });
  assert.equal(result.score, null);
  assert.equal(result.band, 'insufficient-data');
});

test('low-confidence evidence is discounted and cannot score above equivalent high-confidence evidence', () => {
  const input = { cvssBaseScore: 9.8, epss: 0.9, kev: true };
  assert.ok(calculateRiskPriority({ ...input, confidence: 'low' }).score < calculateRiskPriority({ ...input, confidence: 'high' }).score);
});
