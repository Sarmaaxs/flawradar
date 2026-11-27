import './components.js';
import { api, h, scannerInfo } from './dom.js';

const $ = (selector) => document.querySelector(selector);
const state = { files: [], skippedDirs: [], result: null, previous: null };
let termsVersion = null;

function setStatus(message) {
  $('#causal-status').textContent = message || '';
  $('#causal-status').hidden = !message;
}
function setError(message) {
  $('#causal-error').textContent = message || '';
  $('#causal-error').hidden = !message;
  if (message) setStatus('');
}
function card(title, detail, meta = '') {
  const article = h('article', { class: 'intel-finding' });
  article.append(h('div', { class: 'intel-finding-head' }, h('strong', {}, title)));
  if (detail) article.append(h('p', {}, detail));
  if (meta) article.append(h('p', { class: 'muted' }, meta));
  return article;
}
function showList(selector, rows, emptyText, makeCard) {
  const root = $(selector);
  root.replaceChildren();
  if (!rows.length) {
    root.append(h('p', { class: 'intel-empty' }, emptyText));
    return;
  }
  rows.forEach((row) => root.append(makeCard(row)));
}

$('#causal-drop').addEventListener('w-files', (event) => {
  state.files = event.detail.files || [];
  state.skippedDirs = event.detail.skippedDirs || [];
  $('#causal-selection').textContent = state.files.length
    ? state.files.length + ' files selected' + (state.skippedDirs.length ? ' · skipped folders: ' + state.skippedDirs.join(', ') : '')
    : 'No source files selected.';
  setError('');
});

async function readSelectedFiles() {
  const skipNames = new Set(['node_modules', '.git', '.svn', '.hg', 'vendor', 'dist', 'build', '.next', '.nuxt', '.cache', '__pycache__', 'venv', '.venv', 'bower_components', 'coverage', '.idea', '.vscode', 'target']);
  const selected = state.files.filter((item) => !item.path.split('/').some((part) => skipNames.has(part)));
  if (!selected.length) throw new Error('No readable source files were selected.');
  if (selected.length > 3000) throw new Error('The limit is 3,000 files.');
  if (selected.some((item) => /\.zip$/i.test(item.path))) throw new Error('Extract the ZIP first, then choose the extracted folder.');
  const files = [];
  let total = 0;
  for (let i = 0; i < selected.length; i += 1) {
    const item = selected[i];
    if (i % 20 === 0) setStatus('Reading source files: ' + i + ' of ' + selected.length);
    if (item.file.size > 512 * 1024) continue;
    const content = await item.file.text();
    if (content.includes('\0')) continue;
    total += content.length;
    if (total > 9 * 1024 * 1024) throw new Error('The selected source text exceeds the 9 MB browser upload limit.');
    files.push({ path: item.path.replace(/^\/+/, ''), content });
  }
  if (!files.length) throw new Error('No readable source files were found. Files over 512 KB and binary files are skipped.');
  return files;
}

$('#causal-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  setError('');
  const host = $('#causal-host').value.trim();
  if (!host) return setError('Enter the domain you own.');
  if (!$('#causal-terms').checked) return setError('Confirm authorization and acceptance of the terms.');
  if (!state.files.length) return setError('Choose the source folder or source files first.');
  const button = $('#causal-run');
  button.disabled = true;
  button.textContent = 'Building graph…';
  try {
    if (!termsVersion) termsVersion = (await scannerInfo()).termsVersion;
    const files = await readSelectedFiles();
    setStatus('Checking domain ownership and investigating public evidence…');
    const result = await api('/api/causal', {
      method: 'POST',
      body: JSON.stringify({ host, terms: termsVersion, files, previous: state.previous }),
    });
    if (state.skippedDirs.length) result.notices.push('Skipped folders: ' + state.skippedDirs.join(', ') + '.');
    state.previous = result;
    state.result = result;
    setStatus('');
    render(result);
  } catch (error) {
    setError(error.message || 'The causal analysis failed.');
  } finally {
    button.disabled = false;
    button.textContent = 'Build causal graph';
  }
});

function render(result) {
  $('#causal-results').hidden = false;
  $('#causal-result-host').textContent = result.host || 'Causal exposure report';
  $('#causal-generated').textContent = 'Generated ' + new Date(result.generatedAt).toLocaleString();
  $('#causal-nodes').textContent = result.summary.nodes;
  $('#causal-edges').textContent = result.summary.edges;
  $('#causal-routes').textContent = result.summary.matchedRoutes;
  $('#causal-paths').textContent = result.summary.candidatePaths;
  $('#causal-high').textContent = result.summary.highConfidencePaths;

  showList('#causal-path-list', result.paths || [], 'No candidate endpoint-to-sink or dependency paths were correlated.', (path) => {
    const score = path.priority?.score == null ? 'Insufficient threat-intelligence data' : 'Priority heuristic: ' + path.priority.score + '/100 (' + path.priority.band + ')';
    const guards = (path.guards || []).map((item) => item.control + ' at line ' + item.line).join(', ');
    return card(path.entry + ' → ' + path.sink, path.status.replaceAll('-', ' '), 'Severity: ' + (path.severity || 'unknown') + ' · Confidence: ' + path.confidence + ' · ' + score + (path.file ? ' · ' + path.file + ':' + path.line : '') + (guards ? ' · Observed guards: ' + guards : ''));
  });

  const drift = (result.nodes || []).filter((node) => ['surface-version-drift', 'domain-advisory', 'dependency-advisory'].includes(node.type));
  showList('#causal-drift-list', drift, 'No dependency advisories or live/source version disagreements were identified.', (node) => card(node.label, node.detail, node.type.replaceAll('-', ' ') + ' · ' + (node.confidence || 'unknown') + ' confidence'));

  const temporal = result.temporal;
  const temporalRows = temporal ? [
    ...(temporal.newAdvisories || []).map((item) => ({ title: 'New advisory: ' + item.label, detail: 'Severity: ' + (item.severity || 'unknown') + ' · KEV: ' + (item.kev ? 'listed' : 'not listed') })),
    ...(temporal.maturityChanges || []).map((item) => ({ title: 'Advisory maturity changed: ' + item.label, detail: 'EPSS/KEV intelligence changed since the previous graph.' })),
    ...(temporal.newNodes || []).map((item) => ({ title: 'New graph node: ' + item.label, detail: item.type + ' · ' + (item.severity || 'no severity') })),
    ...(temporal.removedNodes || []).map((item) => ({ title: 'Removed graph node: ' + item.label, detail: item.type })),
  ] : [];
  showList('#causal-temporal-list', temporalRows, temporal ? 'No graph or advisory changes were detected against the previous run.' : 'No previous graph was supplied. Run this analysis again in the same page session to compare drift.', (item) => card(item.title, item.detail));

  showList('#causal-fix-list', result.remediation || [], 'No remediation groups were generated from correlated sink findings.', (item) => card(item.fix, item.findings + ' finding(s) · ' + item.paths + ' linked path(s)', 'Counterfactual: ' + (item.impact?.candidatePathsEliminated ?? 0) + ' candidate path(s) eliminated · ' + (item.impact?.candidatePathsRemaining ?? result.paths.length) + ' remaining. ' + (item.impact?.note || '')));

  showList('#causal-witness-list', result.verificationWitnesses || [], 'No candidate paths require manual verification.', (witness) => {
    const article = card('Manual verification · ' + witness.pathId, 'No payload generated. No network probe sent.');
    const list = h('ol');
    (witness.steps || []).forEach((step) => list.append(h('li', {}, step)));
    article.append(list);
    if (witness.observedGuards?.length) article.append(h('p', { class: 'muted' }, 'Observed guards: ' + witness.observedGuards.map((item) => item.control + ' at line ' + item.line).join(', ')));
    return article;
  });

  const types = [...new Set((result.nodes || []).map((node) => node.type))].sort();
  $('#causal-node-filter').replaceChildren(new Option('All', 'all'), ...types.map((type) => new Option(type.replaceAll('-', ' '), type)));
  renderNodes();

  showList('#causal-notices', result.notices || [], 'No additional notices.', (notice) => card('Notice', notice));
  $('#causal-limitations').textContent = (result.limitations || []).join(' ');
  $('#causal-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderNodes() {
  if (!state.result) return;
  const type = $('#causal-node-filter').value;
  const nodes = state.result.nodes.filter((node) => type === 'all' || node.type === type);
  showList('#causal-graph-list', nodes, 'No graph nodes match this filter.', (node) => card(node.label, node.detail || '', node.type.replaceAll('-', ' ') + ' · ' + (node.confidence || 'unknown') + ' confidence' + (node.file ? ' · ' + node.file + ':' + node.line : '')));
}
$('#causal-node-filter').addEventListener('change', renderNodes);

$('#causal-export').addEventListener('click', () => {
  if (!state.result) return;
  const blob = new Blob([JSON.stringify(state.result, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'flawradar-' + (state.result.host || 'causal') + '-causal.json';
  anchor.click();
  URL.revokeObjectURL(url);
});
$('#causal-reset').addEventListener('click', () => {
  state.files = [];
  state.skippedDirs = [];
  state.result = null;
  state.previous = null;
  $('#causal-results').hidden = true;
  $('#causal-host').value = '';
  $('#causal-terms').checked = false;
  $('#causal-selection').textContent = 'No source files selected.';
  $('#causal-drop').replaceChildren();
  // Rebuilding the custom element restores its file-picker controls.
  $('#causal-drop').remove();
  const drop = document.createElement('w-dropzone');
  drop.id = 'causal-drop';
  $('#causal-selection').before(drop);
  drop.addEventListener('w-files', (event) => {
    state.files = event.detail.files || [];
    state.skippedDirs = event.detail.skippedDirs || [];
    $('#causal-selection').textContent = state.files.length ? state.files.length + ' files selected' : 'No source files selected.';
  });
  setError('');
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
scannerInfo().then((info) => { termsVersion = info.termsVersion; }).catch((error) => setError(error.message));
