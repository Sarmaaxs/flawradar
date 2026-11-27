import { calculateRiskPriority } from './risk.js';
import { collectPackages } from '../source/cves.js';

const SEVERITY = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const clean = (value, max = 500) => String(value ?? '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max);
const unique = (items) => [...new Set(items)];
const routePatterns = [
  /\b(?:app|router|server)\.(?:get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`?#]+)/gi,
  /\b(?:route|app)\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`?#]+)/gi,
  /@(?:app|router)\.route\s*\(\s*['"`]([^'"`?#]+)/gi,
  /\bRoute::(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`?#]+)/gi,
  /\b(?:http\.HandleFunc|HandleFunc)\s*\(\s*['"`]([^'"`?#]+)/gi,
];

function sourceRoutes(files) {
  const routes = [];
  for (const file of files) {
    const rows = String(file.content || '').split('\n');
    for (let i = 0; i < rows.length; i += 1) {
      for (const pattern of routePatterns) {
        pattern.lastIndex = 0;
        for (const match of rows[i].matchAll(pattern)) {
          const path = clean(match[1], 180);
          if (!path.startsWith('/')) continue;
          routes.push({ id: 'source-route:' + file.path + ':' + (i + 1) + ':' + path, path, file: file.path, line: i + 1, evidence: clean(rows[i], 220) });
        }
      }
    }
  }
  return routes.slice(0, 500);
}

function pathOfEndpoint(node) {
  const label = String(node.label || '');
  return label.startsWith('/') ? label.split('?')[0] : null;
}

function samePath(a, b) {
  const normal = (s) => s.replace(/\/$/, '') || '/';
  if (normal(a) === normal(b)) return true;
  const aa = normal(a).split('/').filter(Boolean);
  const bb = normal(b).split('/').filter(Boolean);
  return aa.length === bb.length && aa.every((part, i) => part.startsWith(':') || part.startsWith('{') || part === bb[i] || bb[i]?.startsWith(':') || bb[i]?.startsWith('{'));
}

function sourceControls(files, filePath, startLine = 1, endLine = 100) {
  const file = files.find((item) => item.path === filePath);
  const rows = String(file?.content || '').split('\n');
  const window = rows.slice(Math.max(0, startLine - 1), Math.min(rows.length, Math.max(endLine, startLine) + 80));
  const evidence = [];
  const flags = {
    auth: /\b(?:auth|authenticate|isAuthenticated|requireAuth|verifyToken|passport\.authenticate|login_required|auth_required|middleware.*jwt)\b/i,
    validation: /\b(?:validator|sanitize|schema|zod|joi|yup|parseInt|parseFloat|isValid|validate|allowlist|allow_list|Number\.isInteger|typeof)\b/i,
    regexGuard: /\.test\s*\(|\.match\s*\(|new RegExp\s*\(/i,
    sanitizer: /\b(?:sanitize|escape|DOMPurify|validator\.)\w*\s*\(/i,
    earlyReject: /\b(?:throw|return)\b.*(?:400|401|403|invalid|unauthori[sz]ed|forbidden)/i,
  };
  const found = Object.fromEntries(Object.keys(flags).map((key) => [key, false]));
  window.forEach((line, index) => {
    for (const [key, pattern] of Object.entries(flags)) {
      if (pattern.test(line)) {
        found[key] = true;
        if (evidence.length < 12) evidence.push({ line: Math.max(0, startLine - 1) + index + 1, text: clean(line, 180), control: key });
      }
    }
  });
  return { ...found, evidence };
}

function addNode(nodes, byId, node) {
  if (byId.has(node.id)) return byId.get(node.id);
  const value = { confidence: 'medium', ...node };
  nodes.push(value);
  byId.set(value.id, value);
  return value;
}

function addEdge(edges, seen, from, to, relation, confidence = 'medium') {
  if (!from || !to || from === to) return;
  const key = [from, to, relation].join('|');
  if (seen.has(key)) return;
  seen.add(key);
  edges.push({ from, to, relation, confidence });
}

function temporalDelta(previous, current) {
  if (!previous || !Array.isArray(previous.nodes) || !Array.isArray(previous.edges)) return null;
  const oldNodes = new Map(previous.nodes.map((node) => [node.id, node]));
  const newNodes = new Map(current.nodes.map((node) => [node.id, node]));
  const oldEdges = new Set(previous.edges.map((edge) => [edge.from, edge.to, edge.relation].join('|')));
  const newEdges = new Set(current.edges.map((edge) => [edge.from, edge.to, edge.relation].join('|')));
  const advisoryTypes = new Set(['domain-advisory', 'dependency-advisory']);
  const newAdvisories = [...newNodes.values()].filter((node) => advisoryTypes.has(node.type) && !oldNodes.has(node.id)).map((node) => ({ id: node.id, label: node.label, severity: node.severity || null, epss: node.meta?.epss || null, kev: node.meta?.kev || null }));
  const maturityChanges = [...newNodes.values()].filter((node) => {
    if (!advisoryTypes.has(node.type) || !oldNodes.has(node.id)) return false;
    const before = oldNodes.get(node.id).meta || {};
    const after = node.meta || {};
    return JSON.stringify(before.epss || null) !== JSON.stringify(after.epss || null) || Boolean(before.kev) !== Boolean(after.kev);
  }).map((node) => ({ id: node.id, label: node.label, before: { epss: oldNodes.get(node.id).meta?.epss || null, kev: oldNodes.get(node.id).meta?.kev || null }, after: { epss: node.meta?.epss || null, kev: node.meta?.kev || null } }));
  return {
    newNodes: [...newNodes.values()].filter((node) => !oldNodes.has(node.id)).map((node) => ({ id: node.id, type: node.type, label: node.label, severity: node.severity || null })),
    removedNodes: [...oldNodes.values()].filter((node) => !newNodes.has(node.id)).map((node) => ({ id: node.id, type: node.type, label: node.label })),
    changedNodes: [...newNodes.values()].filter((node) => oldNodes.has(node.id) && (node.severity !== oldNodes.get(node.id).severity || node.confidence !== oldNodes.get(node.id).confidence)).map((node) => ({ id: node.id, before: { severity: oldNodes.get(node.id).severity || null, confidence: oldNodes.get(node.id).confidence }, after: { severity: node.severity || null, confidence: node.confidence } })),
    newEdges: [...newEdges].filter((edge) => !oldEdges.has(edge)),
    removedEdges: [...oldEdges].filter((edge) => !newEdges.has(edge)),
    newAdvisories,
    maturityChanges,
  };
}

/**
 * Correlates passive domain evidence with in-memory source analysis.
 * It never sends generated payloads or invokes a vulnerability sink.
 */
export function buildCausalExposure({ domain, source, files, previous = null }) {
  const nodes = [];
  const edges = [];
  const byId = new Map();
  const edgeSet = new Set();
  const notices = [];
  const routes = sourceRoutes(files);
  const sourceFindings = Array.isArray(source?.findings) ? source.findings : [];
  const domainNodes = Array.isArray(domain?.nodes) ? domain.nodes : [];
  const endpoints = domainNodes.filter((node) => node.type === 'endpoint' || node.type === 'entry-point');
  const technologies = domainNodes.filter((node) => node.type === 'technology');
  const domainCves = domainNodes.filter((node) => node.type === 'cve');
  const protocolEvidence = domainNodes.filter((node) => ['certificate', 'tls', 'network-path', 'network-hop'].includes(node.type));
  const rootId = 'causal-root:' + clean(domain?.host || 'unknown', 180);

  addNode(nodes, byId, { id: rootId, type: 'application', label: clean(domain?.host || 'Application', 180), confidence: 'high', source: 'Authorized passive domain investigation' });

  for (const observation of protocolEvidence) {
    const id = 'protocol-evidence:' + observation.id;
    addNode(nodes, byId, { id, type: 'protocol-observation', label: clean(observation.label, 180), detail: clean(observation.detail, 450), confidence: observation.confidence || 'medium', evidence: observation.source || 'TLS/network observation' });
    addEdge(edges, edgeSet, rootId, id, 'observed-protocol-or-network-evidence', observation.confidence || 'medium');
  }

  for (const endpoint of endpoints) {
    const endpointPath = pathOfEndpoint(endpoint);
    const id = 'domain:' + endpoint.id;
    addNode(nodes, byId, { id, type: 'external-entry', label: clean(endpoint.label, 180), detail: clean(endpoint.detail, 450), confidence: endpoint.confidence || 'medium', evidence: endpoint.source || 'Domain intelligence' });
    addEdge(edges, edgeSet, rootId, id, 'exposes-or-references', endpoint.confidence || 'medium');
    if (!endpointPath) continue;
    const matches = routes.filter((route) => samePath(endpointPath, route.path));
    for (const route of matches) {
      addNode(nodes, byId, { id: route.id, type: 'source-route', label: route.path, file: route.file, line: route.line, detail: route.evidence, confidence: 'medium', evidence: 'Route declaration matched by path' });
      addEdge(edges, edgeSet, id, route.id, 'candidate-domain-to-code-match', 'medium');
      const related = sourceFindings.filter((finding) => finding.file === route.file && finding.detection?.sinkLine);
      for (const finding of related) {
        const sinkId = 'source-sink:' + finding.file + ':' + finding.line + ':' + finding.ruleId;
        const controls = sourceControls(files, route.file, route.line, finding.line);
        const confidence = controls.auth || controls.validation || controls.sanitizer || controls.regexGuard ? 'low' : (finding.confidence || 'medium');
        addNode(nodes, byId, { id: sinkId, type: 'potential-sink', label: clean(finding.title, 180), detail: clean(finding.why, 450), file: finding.file, line: finding.line, severity: finding.severity, confidence, ruleId: finding.ruleId, fix: clean(finding.fix, 500), controls });
        addEdge(edges, edgeSet, route.id, sinkId, 'same-file-taint-candidate', confidence);
      }
    }
    if (!matches.length) notices.push('No source route declaration matched domain endpoint ' + endpointPath + '; cross-framework or indirect routing may not be recognized.');
  }

  for (const finding of sourceFindings.filter((item) => item.ruleId && !item.detection?.sinkLine)) {
    const id = 'source-finding:' + finding.file + ':' + finding.line + ':' + finding.ruleId;
    addNode(nodes, byId, { id, type: 'source-finding', label: clean(finding.title, 180), detail: clean(finding.why, 450), file: finding.file, line: finding.line, severity: finding.severity, confidence: finding.confidence || 'medium', fix: clean(finding.fix, 500) });
    addEdge(edges, edgeSet, rootId, id, 'source-analysis-finding', finding.confidence || 'medium');
  }

  // Resolve supported lockfile inventory. A route is linked only when its file
  // contains a literal import/require reference; otherwise reachability stays unknown.
  const inventory = collectPackages(files);
  notices.push(...inventory.notices);
  for (const pkg of inventory.packages) {
    const packageId = 'source-package:' + pkg.ecosystem + ':' + pkg.name + ':' + pkg.version;
    addNode(nodes, byId, { id: packageId, type: 'source-dependency', label: clean(pkg.name + '@' + pkg.version, 180), detail: 'Resolved dependency observed in ' + clean(pkg.file, 180), confidence: 'high', evidence: 'Uploaded dependency manifest', ecosystem: pkg.ecosystem, version: pkg.version, manifest: pkg.file });
    const packageFindings = sourceFindings.filter((finding) => finding.package === pkg.name && finding.version === pkg.version);
    for (const finding of packageFindings) {
      const advisoryId = 'source-advisory:' + finding.ruleId + ':' + finding.file + ':' + finding.line;
      addNode(nodes, byId, { id: advisoryId, type: 'dependency-advisory', label: clean(finding.cve || finding.title, 180), detail: clean(finding.why, 450), severity: finding.severity, confidence: finding.confidence || 'medium', package: finding.package, version: finding.version, fix: clean(finding.fix, 500), meta: { cvssBaseScore: finding.cvssBaseScore ?? null, cvss: finding.cvss ?? null, epss: finding.epss ?? null, kev: finding.kev ?? null } });
      addEdge(edges, edgeSet, packageId, advisoryId, 'affected-by-advisory', finding.confidence || 'medium');
    }
    const escapedPackage = String(pkg.name).replace(/[.*+?^\x24{}()|[\]\\]/g, '\\$&');
    const importPattern = new RegExp("(?:from\\s*|require\\s*\\(|import\\s*\\()(['\"])"+ escapedPackage + "\\1");
    for (const file of files) {
      if (!importPattern.test(String(file.content || ''))) continue;
      const sourceFileId = 'source-file:' + file.path;
      addNode(nodes, byId, { id: sourceFileId, type: 'source-file', label: clean(file.path, 180), confidence: 'medium', evidence: 'Literal import/require reference' });
      addEdge(edges, edgeSet, packageId, sourceFileId, 'direct-import-observed', 'medium');
      for (const route of routes.filter((item) => item.file === file.path)) {
        addEdge(edges, edgeSet, route.id, packageId, 'route-file-imports-dependency', 'medium');
      }
    }
    const matchingTech = technologies.find((tech) => {
      const observedName = String(tech.meta?.name || '').toLowerCase();
      const packageName = pkg.name.toLowerCase();
      return observedName === packageName || packageName.endsWith('/' + observedName) || observedName.endsWith('/' + packageName);
    });
    if (matchingTech && matchingTech.meta?.version && String(matchingTech.meta.version) !== String(pkg.version)) {
      const driftId = 'surface-version-drift:' + pkg.name + ':' + matchingTech.meta.version + ':' + pkg.version;
      addNode(nodes, byId, { id: driftId, type: 'surface-version-drift', label: 'Live/source version disagreement: ' + clean(pkg.name, 100), detail: 'Public fingerprint reports ' + clean(matchingTech.meta.version, 80) + ' while the supplied manifest resolves ' + clean(pkg.version, 80) + '. This may indicate deployment drift, CDN separation or fingerprint uncertainty.', confidence: 'low', severity: 'info' });
      addEdge(edges, edgeSet, 'domain-tech:' + matchingTech.id, driftId, 'live-version-evidence', 'low');
      addEdge(edges, edgeSet, packageId, driftId, 'manifest-version-evidence', 'low');
    }
  }
  for (const tech of technologies) {
    const id = 'domain-tech:' + tech.id;
    addNode(nodes, byId, { id, type: 'observed-technology', label: clean(tech.label, 180), detail: clean(tech.detail, 350), confidence: tech.confidence || 'medium', evidence: tech.source || 'Passive fingerprint' });
    addEdge(edges, edgeSet, rootId, id, 'observed-technology', tech.confidence || 'medium');

  }

  for (const cve of domainCves) {
    const id = 'domain-cve:' + cve.id;
    addNode(nodes, byId, { id, type: 'domain-advisory', label: clean(cve.label, 180), detail: clean(cve.detail, 450), severity: cve.severity, confidence: cve.confidence || 'medium', evidence: cve.source || 'Domain intelligence', meta: cve.meta || {} });
    const pkg = String(cve.meta?.package || '').toLowerCase();
    const techMatch = pkg ? technologies.find((tech) => String(tech.meta?.name || tech.label).toLowerCase().includes(pkg) || pkg.includes(String(tech.meta?.name || '').toLowerCase())) : null;
    if (techMatch) addEdge(edges, edgeSet, 'domain-tech:' + techMatch.id, id, 'observed-version-advisory-match', 'medium');
    else addEdge(edges, edgeSet, rootId, id, 'domain-advisory-candidate', 'low');
  }

  const paths = [];
  for (const edge of edges.filter((item) => item.relation === 'same-file-taint-candidate')) {
    const sink = byId.get(edge.to);
    const route = byId.get(edge.from);
    const priority = calculateRiskPriority({ severity: sink.severity, confidence: sink.confidence }, { exposure: sink.confidence === 'high' ? 1 : 0.5 });
    paths.push({ id: 'path:' + edge.from + ':' + edge.to, entry: route.label, sink: sink.label, file: sink.file, line: sink.line, severity: sink.severity, confidence: sink.confidence, priority, preconditions: { authGateObserved: Boolean(sink.controls?.auth), validationObserved: Boolean(sink.controls?.validation), sanitizerObserved: Boolean(sink.controls?.sanitizer), regexGuardObserved: Boolean(sink.controls?.regexGuard) }, guards: sink.controls?.evidence || [], status: 'candidate-not-exploit-verified' });
  }
  for (const edge of edges.filter((item) => item.relation === 'route-file-imports-dependency')) {
    const route = byId.get(edge.from);
    const packageNode = byId.get(edge.to);
    for (const advisoryEdge of edges.filter((item) => item.from === packageNode?.id && item.relation === 'affected-by-advisory')) {
      const advisory = byId.get(advisoryEdge.to);
      const priority = calculateRiskPriority({ severity: advisory?.severity, confidence: advisory?.confidence, cvssBaseScore: advisory?.meta?.cvssBaseScore, epss: advisory?.meta?.epss, kev: advisory?.meta?.kev }, { exposure: 0.5 });
      paths.push({ id: 'path:' + edge.from + ':' + advisoryEdge.to, entry: route?.label || 'source route', sink: advisory?.label || 'dependency advisory', package: packageNode?.label, severity: advisory?.severity, confidence: 'low', priority, status: 'candidate-import-reachability-not-function-call' });
    }
  }

  const remediation = new Map();
  for (const node of nodes.filter((item) => ['potential-sink', 'dependency-advisory'].includes(item.type) && item.fix)) {
    const key = node.fix;
    const current = remediation.get(key) || { fix: key, findings: 0, paths: 0, findingIds: [] };
    current.findings += 1;
    current.paths += paths.filter((path) => (path.file === node.file && path.line === node.line) || path.sink === node.label).length;
    current.findingIds.push(node.id);
    remediation.set(key, current);
  }

  const remediationPlans = [...remediation.values()].map((item) => {
    const eliminated = paths.filter((path) => item.findingIds.some((id) => path.id.includes(id)));
    return {
      ...item,
      impact: {
        model: 'evidence-linked-remediation-simulation-v1',
        candidatePathsEliminated: eliminated.length,
        candidatePathsRemaining: Math.max(0, paths.length - eliminated.length),
        eliminatedPathIds: eliminated.map((path) => path.id),
        note: 'Counterfactual based only on graph links to the selected finding IDs; it does not apply a patch or prove that unrelated paths are fixed.',
      },
    };
  }).sort((a, b) => b.impact.candidatePathsEliminated - a.impact.candidatePathsEliminated || b.findings - a.findings).slice(0, 30);

  const result = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    host: clean(domain?.host || '', 180),
    nodes,
    edges,
    paths,
    remediation: remediationPlans,
    summary: {
      nodes: nodes.length,
      edges: edges.length,
      domainEndpoints: endpoints.length,
      matchedRoutes: nodes.filter((node) => node.type === 'source-route').length,
      candidatePaths: paths.length,
      highConfidencePaths: paths.filter((path) => path.confidence === 'high').length,
      unmatchedEndpoints: notices.length,
    },
    verificationWitnesses: paths.slice(0, 20).map((path) => ({
      pathId: path.id,
      mode: 'manual-safe-verification',
      preconditions: path.preconditions || null,
      observedGuards: path.guards || [],
      steps: [
        'Confirm the route is in scope and use a non-production test account.',
        'Review the identified source line and its authorization and validation controls.',
        'Use a harmless, unique marker or ordinary type-valid input in a controlled test environment.',
        'Verify the expected response and confirm no state change or sensitive data access occurred.',
      ],
      generatedPayload: null,
      networkProbeSent: false,
    })),
    limitations: [
      'Domain-to-code matches are candidate correlations, not proof that the deployed source is identical.',
      'Taint paths are limited by the existing same-file source analyzer; cross-file and interprocedural flow is not claimed.',
      'Guard extraction is pattern-based and does not prove that a guard dominates every path to a sink.',
      'No exploit payloads are generated or transmitted. Verification witnesses are safe analyst procedures only.',
      'An observed technology or CVE match does not prove the vulnerable function is reachable.',
    ],
    notices: unique(notices).slice(0, 100),
  };
  result.temporal = temporalDelta(previous, result);
  return result;
}
