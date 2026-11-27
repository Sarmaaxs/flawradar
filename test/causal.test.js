import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCausalExposure } from '../server/scanner/causal.js';

const files = [
  {
    path: 'src/routes.js',
    content: [
      "app.get('/api/users/:id', requireAuth, async (req, res) => {",
      '  const id = req.query.id;',
      '  db.query("SELECT * FROM users WHERE id=" + id);',
      '});',
    ].join('\n'),
  },
];
const source = {
  findings: [{
    ruleId: 'flow-sql', title: 'Request data reaches SQL query', severity: 'high', confidence: 'medium',
    file: 'src/routes.js', line: 3, why: 'Request data may be concatenated into SQL.',
    fix: 'Use parameterized queries.',
    detection: { method: 'context-weighted-taint-correlation', sourceLine: 2, sinkLine: 3 },
  }],
  summary: { high: 1 },
};
const domain = {
  host: 'example.test',
  nodes: [
    { id: 'endpoint:/api/users/:id', type: 'endpoint', label: '/api/users/:id', detail: 'Endpoint referenced by public JavaScript.', confidence: 'medium', source: 'Static page analysis' },
    { id: 'tech:express', type: 'technology', label: 'Express 4.18.2', detail: 'Server fingerprint', confidence: 'high', source: 'Passive fingerprint', meta: { name: 'Express', version: '4.18.2' } },
    { id: 'cve:CVE-2024-12345', type: 'cve', label: 'CVE-2024-12345', detail: 'Advisory candidate', severity: 'high', confidence: 'medium', source: 'OSV', meta: { package: 'express' } },
  ],
};

test('causal graph aligns observed endpoints with source routes and same-file sinks', () => {
  const result = buildCausalExposure({ domain, source, files });
  assert.equal(result.summary.domainEndpoints, 1);
  assert.equal(result.summary.matchedRoutes, 1);
  assert.equal(result.summary.candidatePaths, 1);
  assert.ok(result.edges.some((edge) => edge.relation === 'candidate-domain-to-code-match'));
  assert.ok(result.edges.some((edge) => edge.relation === 'same-file-taint-candidate'));
  assert.equal(result.verificationWitnesses[0].networkProbeSent, false);
  assert.equal(result.verificationWitnesses[0].generatedPayload, null);
  assert.equal(result.remediation[0].impact.candidatePathsEliminated, 1);
  assert.equal(result.remediation[0].impact.candidatePathsRemaining, 0);
  assert.match(result.limitations.join(' '), /same-file/);
});

test('authorization and validation signals lower confidence rather than asserting exploitability', () => {
  const guardedFiles = [{
    path: 'src/routes.js',
    content: "app.get('/api/users/:id', requireAuth, validateUserId, handler);\n// auth validator",
  }];
  const guardedSource = {
    findings: [{ ...source.findings[0], file: 'src/routes.js', line: 3 }],
  };
  const result = buildCausalExposure({ domain, source: guardedSource, files: guardedFiles });
  const sink = result.nodes.find((node) => node.type === 'potential-sink');
  assert.equal(sink.confidence, 'low');
  assert.equal(sink.controls.auth, true);
  assert.equal(sink.controls.validation, true);
});

test('temporal comparison identifies new and removed graph relationships', () => {
  const previous = buildCausalExposure({ domain: { host: 'example.test', nodes: [] }, source: { findings: [] }, files: [] });
  const current = buildCausalExposure({ domain, source, files, previous });
  assert.ok(current.temporal);
  assert.ok(current.temporal.newNodes.length > 0);
  assert.ok(current.temporal.newEdges.length > 0);
  assert.ok(current.temporal.newAdvisories.length > 0);
});

test('supply-chain advisory is linked to a route only when a literal package import is observed', () => {
  const appFiles = [
    { path: 'src/routes.js', content: "import express from 'express';\napp.get('/api/users/:id', handler);" },
    { path: 'package-lock.json', content: JSON.stringify({ name: 'demo', lockfileVersion: 2, packages: { '': { name: 'demo' }, 'node_modules/express': { version: '4.18.2' } } }) },
  ];
  const packageSource = {
    findings: [{
      ruleId: 'cve-known', title: 'CVE-2024-11111 in express@4.18.2', severity: 'high', confidence: 'high',
      file: 'package-lock.json', line: 1, package: 'express', version: '4.18.2', ecosystem: 'npm',
      cve: 'CVE-2024-11111', why: 'Affected dependency version.', fix: 'Upgrade express.',
    }],
  };
  const result = buildCausalExposure({ domain: { host: 'example.test', nodes: [] }, source: packageSource, files: appFiles });
  assert.ok(result.nodes.some((node) => node.type === 'source-dependency' && node.label === 'express@4.18.2'));
  assert.ok(result.edges.some((edge) => edge.relation === 'route-file-imports-dependency'));
  assert.ok(result.paths.some((path) => path.status === 'candidate-import-reachability-not-function-call'));
});

test('public fingerprint and resolved manifest disagreement is recorded as low-confidence drift', () => {
  const lock = JSON.stringify({ name: 'demo', lockfileVersion: 2, packages: { '': { name: 'demo' }, 'node_modules/express': { version: '4.18.2' } } });
  const result = buildCausalExposure({
    domain: { host: 'example.test', nodes: [{ id: 'tech:express', type: 'technology', label: 'Express 5.0.0', confidence: 'high', source: 'Passive fingerprint', meta: { name: 'Express', version: '5.0.0' } }] },
    source: { findings: [] },
    files: [{ path: 'package-lock.json', content: lock }],
  });
  const drift = result.nodes.find((node) => node.type === 'surface-version-drift');
  assert.ok(drift);
  assert.equal(drift.confidence, 'low');
});

test('empty inputs produce a bounded graph without claiming a verified path', () => {
  const result = buildCausalExposure({ domain: { host: 'example.test', nodes: [] }, source: { findings: [] }, files: [] });
  assert.equal(result.summary.candidatePaths, 0);
  assert.equal(result.verificationWitnesses.length, 0);
  assert.deepEqual(result.temporal, null);
});
