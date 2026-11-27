import './components.js';
import { api, h, scannerInfo } from './dom.js';

const $ = (s) => document.querySelector(s);
const NS = 'http://www.w3.org/2000/svg';
const state = { host: '', data: null, selected: null, zoom: 1, panX: 0, panY: 0, positions: new Map(), drag: null, moved: false };
const svg = (tag, attrs, value) => {
  const el = document.createElementNS(NS, tag);
  Object.entries(attrs || {}).forEach(([k, v]) => el.setAttribute(k, String(v)));
  if (value) el.textContent = value;
  return el;
};
const el = (tag, value, cls) => {
  const out = document.createElement(tag);
  out.textContent = value || '';
  if (cls) out.className = cls;
  return out;
};
let termsVersion = null;

function error(message) {
  $('#intel-error').textContent = message;
  $('#intel-error').hidden = false;
}
async function loadTerms() {
  const info = await scannerInfo();
  termsVersion = info.termsVersion;
}

$('#intel-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#intel-error').hidden = true;
  const host = $('#intel-host').value.trim();
  if (!host) return error('Enter a domain name.');
  if (!$('#intel-terms').checked) return error('Confirm that you own this domain or have written permission to assess it.');
  const button = $('#intel-prepare');
  button.disabled = true; button.textContent = 'Investigating…';
  try {
    await loadTerms();
    state.host = host;
    const data = await api('/api/intelligence', {
      method: 'POST',
      body: JSON.stringify({ host, terms: termsVersion }),
    });
    state.data = data; state.selected = null;
    showResults(data);
  } catch (err) { error(err.message); }
  finally { button.disabled = false; button.textContent = 'Start investigation'; }
});

function showResults(data) {
  $('#intel-results').hidden = false;
  $('#intel-result-host').textContent = data.host;
  $('#intel-generated').textContent = 'Updated ' + new Date(data.generatedAt).toLocaleString() + ' · ' + data.rootDomain;
  $('#metric-assets').textContent = data.summary.assets;
  $('#metric-edges').textContent = data.summary.relationships;
  $('#metric-subdomains').textContent = data.summary.subdomains;
  $('#metric-tech').textContent = data.summary.technologies;
  $('#metric-cves').textContent = data.summary.vulnerabilities;
  $('#metric-critical').textContent = data.summary.critical;
  $('#metric-priority').textContent = data.summary.highestPriority ? `${data.summary.highestPriority}/100` : '—';
  $('#intel-risk-note').textContent = data.riskModel?.description || 'Priority scores are supplementary triage estimates; review the underlying evidence.';
  renderNetworkPath(data.networkPath);
  const types = Array.from(new Set(data.nodes.map((n) => n.type))).sort();
  $('#intel-type').replaceChildren(new Option('All asset types', 'all'), ...types.map((t) => new Option(t.replaceAll('-', ' '), t)));
  const legend = $('#intel-legend'); legend.replaceChildren();
  types.forEach((t) => legend.append(h('div', { class: 'intel-legend-item' }, h('i', { class: 'legend-dot type-' + t }), t.replaceAll('-', ' '))));
  renderGraph();
  renderFindings();
  const notices = $('#intel-notices'); notices.replaceChildren();
  (data.notices || []).forEach((n) => notices.append(el('p', n, 'intel-notice')));

  $('#intel-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderNetworkPath(path) {
  const summary = $('#intel-path-summary');
  const list = $('#intel-path-hops');
  list.replaceChildren();
  if (!path || !Array.isArray(path.hops) || !path.hops.length) {
    summary.textContent = path?.notice || 'No route data was returned by this worker.';
    return;
  }
  const metrics = path.metrics || {};
  summary.textContent = `${path.destination} · ${metrics.hopsObserved ?? path.hops.length} hops · ${metrics.destinationReached ? 'destination reached' : 'destination not confirmed'} · mean RTT ${metrics.meanRttMs == null ? 'n/a' : metrics.meanRttMs + ' ms'} · response rate ${metrics.responseRatePercent ?? 0}%`;
  for (const hop of path.hops) {
    const item = document.createElement('li');
    const address = hop.addresses?.length ? hop.addresses.join(', ') : 'No response';
    const rtt = hop.rttsMs?.length ? hop.rttsMs.map((value) => `${value} ms`).join(' / ') : 'timeout';
    item.textContent = `Hop ${hop.ttl} · ${address} · ${rtt} · ${hop.lossPercent}% probe loss`;
    list.append(item);
  }
}

function positionsFor(nodes, edges) {
  const root = nodes.find((n) => n.type === 'domain') || nodes[0];
  if (!root) return new Map();
  const adjacent = new Map(nodes.map((n) => [n.id, []]));
  edges.forEach((e) => {
    if (adjacent.has(e.source)) adjacent.get(e.source).push(e.target);
    if (adjacent.has(e.target)) adjacent.get(e.target).push(e.source);
  });
  const depth = new Map([[root.id, 0]]), queue = [root.id];
  while (queue.length) {
    const id = queue.shift();
    (adjacent.get(id) || []).forEach((next) => {
      if (!depth.has(next)) { depth.set(next, depth.get(id) + 1); queue.push(next); }
    });
  }
  const buckets = new Map();
  nodes.filter((n) => n.id !== root.id).forEach((n) => {
    const d = Math.min(3, depth.get(n.id) || 3);
    if (!buckets.has(d)) buckets.set(d, []);
    buckets.get(d).push(n);
  });
  const points = new Map([[root.id, { x: 600, y: 410 }]]);
  buckets.forEach((items, d) => {
    items.sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label));
    const baseRadius = d === 1 ? 230 : d === 2 ? 460 : 690;
    items.forEach((item, i) => {
      const ring = Math.floor(i / 12);
      const slot = i % 12;
      const radius = baseRadius + ring * 145;
      const angle = Math.PI * 2 * slot / Math.min(12, items.length - ring * 12) - Math.PI / 2;
      points.set(item.id, { x: 600 + Math.cos(angle) * radius, y: 410 + Math.sin(angle) * radius });
    });
  });
  return points;
}

function visibleNodes() {
  const query = $('#intel-search').value.trim().toLowerCase();
  const type = $('#intel-type').value;
  const severity = $('#intel-severity').value;
  return state.data.nodes.filter((n) =>
    (type === 'all' || n.type === type) &&
    (severity === 'all' || n.severity === severity) &&
    (!query || [n.label, n.detail, n.id, n.source].join(' ').toLowerCase().includes(query)));
}

function renderGraph() {
  if (!state.data) return;
  const rootSvg = $('#intel-graph'); rootSvg.replaceChildren();
  const nodes = state.data.nodes;
  const shown = new Set(visibleNodes().map((n) => n.id));
  if (state.positions.size !== nodes.length) state.positions = positionsFor(nodes, state.data.edges);
  const points = state.positions;
  const extent = Math.max(600, ...[...points.values()].map((p) => Math.max(Math.abs(p.x - 600), Math.abs(p.y - 410)))) + 130;
  const width = Math.max(1200, extent * 2.15) / state.zoom;
  const height = width * 820 / 1200;
  rootSvg.setAttribute('viewBox', (600 + state.panX - width / 2) + ' ' + (410 + state.panY - height / 2) + ' ' + width + ' ' + height);
  const scene = svg('g', { id: 'graph-scene' });
  state.data.edges.forEach((edge) => {
    if (!shown.has(edge.source) || !shown.has(edge.target)) return;
    const a = points.get(edge.source), b = points.get(edge.target);
    if (!a || !b) return;
    scene.append(svg('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'intel-edge' }));
    scene.append(svg('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 5, class: 'intel-edge-label', 'text-anchor': 'middle' }, edge.relation));
  });
  nodes.forEach((item) => {
    if (!shown.has(item.id)) return;
    const p = points.get(item.id); if (!p) return;
    const isRoot = item.type === 'domain';
    const w = isRoot ? 190 : Math.max(116, Math.min(190, item.label.length * 7 + 28));
    const heightNode = isRoot ? 58 : 44;
    const group = svg('g', { class: 'intel-graph-node type-' + item.type + (item.severity !== 'info' ? ' severity-' + item.severity : ''), 'data-id': item.id, tabindex: '0', role: 'button' });
    group.append(svg('rect', { x: p.x - w / 2, y: p.y - heightNode / 2, width: w, height: heightNode, rx: 5, class: 'node-box' }));
    group.append(svg('text', { x: p.x, y: p.y - 2, 'text-anchor': 'middle', class: 'node-title' }, item.label.length > 26 ? item.label.slice(0, 24) + '…' : item.label));
    group.append(svg('text', { x: p.x, y: p.y + 14, 'text-anchor': 'middle', class: 'node-type' }, item.type.replaceAll('-', ' ')));
    const choose = () => selectNode(item);
    group.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      state.drag = { id: item.id, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY };
      state.moved = false;
      rootSvg.setPointerCapture(event.pointerId);
      event.preventDefault();
    });
    group.addEventListener('click', () => { if (!state.moved) choose(); });
    group.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); } });
    scene.append(group);
  });
  rootSvg.append(scene);
  $('#intel-map-status').textContent = shown.size + ' visible of ' + nodes.length + ' assets · ' + state.data.edges.length + ' relationships';
  if (state.selected && shown.has(state.selected.id)) selectNode(state.selected);
}

function selectNode(item) {
  state.selected = item;
  document.querySelectorAll('.intel-graph-node').forEach((n) => n.classList.toggle('selected', n.dataset.id === item.id));
  const panel = $('#intel-detail'); panel.replaceChildren();
  panel.append(el('h4', item.label));
  panel.append(el('p', item.detail || 'No additional details.'));
  panel.append(el('p', 'Type: ' + item.type + ' · Confidence: ' + item.confidence + ' · Source: ' + item.source, 'muted'));
  if (item.severity !== 'info') panel.append(el('p', 'Severity: ' + item.severity.toUpperCase(), 'severity-label severity-' + item.severity));
  if (item.type === 'cve') {
    const m = item.meta || {};
    const params = new URLSearchParams({
      id: item.label, osv: m.osvId || '', package: m.package || '', version: m.version || '',
      ecosystem: m.ecosystem || 'npm', severity: item.severity, summary: item.detail, fix: m.fix || '', details: m.details || '',
      cvss: m.cvss || '', cvssBase: String(m.cvssBaseScore ?? ''), published: m.published || '', modified: m.modified || '',
      affectedPackages: JSON.stringify(m.affectedPackages || []), epss: JSON.stringify(m.epss || null),
      kev: JSON.stringify(m.kev || null), refs: JSON.stringify(m.references || []),
      ranges: JSON.stringify(m.affectedRanges || []), aliases: JSON.stringify(m.aliases || []),
    });
    panel.append(h('a', { class: 'button', href: '/cve?' + params.toString() }, 'Open CVE analysis'));
  }
  if (item.href) panel.append(h('p', {}, h('a', { href: item.href, target: '_blank', rel: 'noopener noreferrer' }, 'Open public source')));
  if (item.meta && item.meta.fix) panel.append(el('p', 'Developer action: ' + item.meta.fix));
}

function renderFindings() {
  const list = $('#intel-findings-list'); list.replaceChildren();
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const findings = state.data.nodes.filter((n) => n.type === 'finding' || n.type === 'cve').sort((a, b) => {
    const ap = a.meta?.priority?.score; const bp = b.meta?.priority?.score;
    if (ap != null || bp != null) return (bp ?? -1) - (ap ?? -1);
    return order[a.severity] - order[b.severity];
  });
  if (!findings.length) { list.append(el('p', 'No baseline findings or version-specific CVEs were identified. This is not proof of security.', 'intel-empty')); return; }
  findings.forEach((item) => {
    const card = h('article', { class: 'intel-finding severity-' + item.severity });
    card.append(h('div', { class: 'intel-finding-head' }, h('strong', {}, item.label), h('span', { class: 'severity-label severity-' + item.severity }, item.severity.toUpperCase())));
    card.append(el('p', item.detail));
    if (item.type === 'cve' && item.meta?.priority?.score != null) {
      const parts = item.meta.priority.components.map((part) => `${part.name} ${part.value}`).join(' · ');
      card.append(el('p', `FlawRadar priority: ${item.meta.priority.score}/100 · ${item.meta.priority.band.toUpperCase()} (heuristic, not a probability)`, 'intel-priority'));
      if (parts) card.append(el('p', `Score inputs: ${parts}`, 'muted'));
    }
    const locate = h('button', { type: 'button', class: 'small secondary' }, 'Locate in map');
    locate.addEventListener('click', () => {
      $('#intel-search').value = item.label; $('#intel-type').value = 'all'; $('#intel-severity').value = 'all';
      renderGraph(); selectNode(item);
    });
    card.append(locate);
    if (item.type === 'cve') {
      const m = item.meta || {};
      const params = new URLSearchParams({
        id: item.label, osv: m.osvId || '', package: m.package || '', version: m.version || '',
        ecosystem: m.ecosystem || 'npm', severity: item.severity, summary: item.detail,
        fix: m.fix || '', details: m.details || '', cvss: m.cvss || '', cvssBase: String(m.cvssBaseScore ?? ''),
        published: m.published || '', modified: m.modified || '', affectedPackages: JSON.stringify(m.affectedPackages || []),
        epss: JSON.stringify(m.epss || null), kev: JSON.stringify(m.kev || null),
        refs: JSON.stringify(m.references || []), ranges: JSON.stringify(m.affectedRanges || []), aliases: JSON.stringify(m.aliases || []),
      });
      card.append(h('a', { href: '/cve?' + params.toString() }, 'Read advisory'));
    }
    list.append(card);
  });
}

$('#intel-search').addEventListener('input', renderGraph);
$('#intel-type').addEventListener('change', renderGraph);
$('#intel-severity').addEventListener('change', renderGraph);
$('#intel-zoom-in').addEventListener('click', () => { state.zoom = Math.min(2.4, state.zoom * 1.2); renderGraph(); });
$('#intel-zoom-out').addEventListener('click', () => { state.zoom = Math.max(.65, state.zoom / 1.2); renderGraph(); });
$('#intel-fit').addEventListener('click', () => { state.zoom = 1; state.panX = 0; state.panY = 0; renderGraph(); });
const mapSvg = $('#intel-graph');
mapSvg.addEventListener('pointermove', (event) => {
  if (!state.drag) return;
  const rect = mapSvg.getBoundingClientRect();
  const view = mapSvg.viewBox.baseVal;
  if (state.drag.id === '__pan__') {
    state.panX -= (event.clientX - state.drag.startX) / rect.width * view.width;
    state.panY -= (event.clientY - state.drag.startY) / rect.height * view.height;
    state.drag.startX = event.clientX; state.drag.startY = event.clientY; renderGraph(); return;
  }
  const dx = (event.clientX - state.drag.startX) / rect.width * view.width;
  const dy = (event.clientY - state.drag.startY) / rect.height * view.height;
  if (Math.abs(dx) + Math.abs(dy) > 2) state.moved = true;
  const point = state.positions.get(state.drag.id);
  if (point) { state.positions.set(state.drag.id, { x: point.x + dx, y: point.y + dy }); state.drag.startX = event.clientX; state.drag.startY = event.clientY; renderGraph(); }
});
mapSvg.addEventListener('pointerup', () => { state.drag = null; });
mapSvg.addEventListener('pointercancel', () => { state.drag = null; });
mapSvg.addEventListener('pointerdown', (event) => {
  if (event.target.closest('.intel-graph-node')) return;
  if (event.button !== 0) return;
  state.drag = { id: '__pan__', pointerId: event.pointerId, startX: event.clientX, startY: event.clientY };
  mapSvg.setPointerCapture(event.pointerId);
});
$('#intel-new').addEventListener('click', () => {
  state.data = null; state.selected = null; state.positions.clear(); state.panX = 0; state.panY = 0; state.zoom = 1;
  $('#intel-results').hidden = true;
  $('#intel-host').value = ''; $('#intel-terms').checked = false;
  window.scrollTo({ top: 0, behavior: 'smooth' });
});
$('#intel-export').addEventListener('click', () => {
  if (!state.data) return;
  const blob = new Blob([JSON.stringify(state.data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'flawradar-' + state.host + '-intelligence.json'; a.click();
  URL.revokeObjectURL(url);
});
loadTerms().catch((err) => error(err.message));
