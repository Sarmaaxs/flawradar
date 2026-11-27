import { codeTabs } from './components.js';
import { reproduce } from './reproduce.js';
import { crossfade, stagger } from './motion.js';
import { api, deleteTokenFor, forgetDeleteToken, formatDate, h, rememberDeleteToken, rememberedTerms, safeHttpsUrl, scannerInfo } from './dom.js';

const id = location.pathname.split('/').pop();
const $ = (sel) => document.querySelector(sel);

const CATEGORY_ORDER = ['Transport', 'Headers', 'Cookies', 'Content', 'DNS and mail', 'Disclosure', 'Exposure'];
const STATUS_ORDER = { fail: 0, warn: 1, pass: 2, info: 3, skip: 4 };
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const TAB_LABELS = { nginx: 'nginx', apache: 'Apache', express: 'Express', dns: 'DNS', file: 'File' };

let scan = null;

function showProblem(title, ...body) {
  $('#progress').hidden = true;
  $('#result').hidden = true;
  $('#title').textContent = title;
  $('#meta').textContent = '';
  const box = $('#problem');
  box.replaceChildren(h('p', { class: 'alert' }, ...body));
  box.hidden = false;
}

function renderSteps(progress) {
  // The meter moves in whole steps: done steps count fully, the running one counts half.
  const done = progress.filter((s) => s.state === 'done').length + progress.filter((s) => s.state === 'running').length / 2;
  $('#progress').style.setProperty('--p', String(progress.length ? Math.min(1, done / progress.length) : 0));
  $('#steps').replaceChildren(
    ...progress.map((s) =>
      h('li', { class: s.state }, { running: '[ .. ]', done: '[ ok ]', failed: '[fail]' }[s.state] || '[    ]', ' ', s.name),
    ),
  );
}

function findingNode(f) {
  const body = h('div', { class: 'body' });
  if (f.why) body.append(h('p', {}, h('b', {}, 'Why it matters. '), f.why));
  if (f.evidence) body.append(h('pre', { class: 'evidence' }, f.evidence));
  if (f.fix) {
    body.append(h('p', {}, h('b', {}, 'How to fix. '), f.fix.text));
    if (f.fix.snippets && Object.keys(f.fix.snippets).length) body.append(codeTabs(f.fix.snippets, TAB_LABELS));
  }
  const cmd = reproduce(f, scan?.host);
  if (cmd) {
    const copy = document.createElement('w-copy');
    copy.setAttribute('label', 'Run this in a terminal to see it yourself');
    copy.textContent = cmd;
    body.append(copy);
  }
  const ref = safeHttpsUrl(f.ref);
  if (ref) body.append(h('p', {}, h('a', { href: ref, rel: 'noopener noreferrer', target: '_blank' }, 'Reference')));

  return h(
    'details',
    { class: 'finding', 'data-status': f.status, open: f.status === 'fail' },
    h(
      'summary',
      {},
      h('w-status', { value: f.status }),
      h('span', {}, h('span', { class: 'title' }, f.title), h('span', { class: 'sev' }, f.severity), h('span', { class: 'brief' }, f.detail)),
    ),
    body,
  );
}

const VERDICT = {
  A: 'Good news. Your site passes almost everything we check.',
  B: 'Pretty good. A few small things to tidy up.',
  C: 'Okay, but not safe enough yet. Fix the items below.',
  D: 'Weak. Several important protections are missing.',
  F: 'Poor. Fix the items below as soon as you can.',
};

/** A short "what is wrong and what to do" in everyday words, for people who are not security experts. */
function plainWords(r) {
  const box = $('#plain');
  const bad = r.findings.filter((f) => f.status === 'fail' || f.status === 'warn')
    .sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const grade = String(r.grade || '?').charAt(0).toUpperCase();
  const parts = [h('p', {}, h('b', {}, `Your grade is ${r.grade}. `), VERDICT[grade] || '')];
  if (!bad.length) {
    parts.push(h('p', {}, 'Nothing needs fixing right now. Scan again after you change your site.'));
  } else {
    parts.push(h('p', {}, h('b', {}, `${bad.length} thing${bad.length === 1 ? '' : 's'} to fix. Start with these:`)));
    parts.push(h('ol', { class: 'plain' }, ...bad.slice(0, 3).map((f) => {
          return h('li', {}, h('b', {}, f.title), '. ', f.why || f.detail || '', f.fix ? h('span', {}, ' ', h('b', {}, 'What to do: '), f.fix.text) : '');
    })));
    parts.push(h('p', { class: 'muted' }, 'The full list is below. Open any item to see the exact setting to paste.'));
  }
  box.replaceChildren(...parts);
  box.hidden = false;
}

const SVG = 'http://www.w3.org/2000/svg';
function svg(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  el.append(...kids);
  return el;
}

function renderRisk(r) {
  const risk = r.exposure;
  const box = $('#risk');
  if (!risk) { box.hidden = true; return; }
  $('#risk-line').replaceChildren(h('b', {}, `${risk.percent}% modelled chance of a successful attack. `), `Level: ${risk.level}.`);
  $('#risk .riskbar i').style.setProperty('--fill', String(Math.min(1, risk.probability)));
  $('#risk-chains').replaceChildren(...risk.chains.map((c) => h('p', { class: 'alert warn' }, h('b', {}, `${c.name}. `), c.story)));
  const rows = risk.ranked.slice(0, 6).map((x) => h('li', {}, h('b', {}, x.title), `. Fixing it takes the figure from ${risk.percent}% to about ${x.after}%.`));
  $('#risk-order').replaceChildren(...(rows.length ? rows : [h('li', {}, 'Nothing to fix.')]));
  box.hidden = false;
}

/** Radial map: the site in the middle, one dot per request, grouped by step. */
function renderMap(r, host) {
  const reqs = r.requests || [];
  const box = $('#map');
  if (!reqs.length) { box.hidden = true; return; }
  const W = 640;
  const H = 440;
  const cx = W / 2;
  const cy = H / 2;
  const phases = [...new Set(reqs.map((q) => q.phase))];
  const cls = (q) => (q.error || !q.status ? 'se' : `s${Math.floor(q.status / 100)}`);
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Map of ${reqs.length} requests sent to ${host}`, class: 'reqmap' });
  const dots = [];
  phases.forEach((phase, pi) => {
    const items = reqs.filter((q) => q.phase === phase);
    const sector = (2 * Math.PI) / phases.length;
    const mid = pi * sector - Math.PI / 2 + sector / 2;
    const spread = sector * 0.72;
    items.forEach((q, i) => {
      const t = items.length === 1 ? 0.5 : i / (items.length - 1);
      const angle = mid - spread / 2 + spread * t;
      const radius = 96 + (i % 3) * 30;
      const x = cx + Math.cos(angle) * radius;
      const y = cy + Math.sin(angle) * radius;
      const line = svg('line', { x1: cx, y1: cy, x2: x.toFixed(1), y2: y.toFixed(1), class: 'map-line' });
      const dot = svg('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: 6, class: `map-dot ${cls(q)}` }, svg('title', {}, `${q.method} ${q.path}: ${q.error ? q.error : `HTTP ${q.status}`}, ${q.ms} ms`));
      root.append(line, dot);
      dots.push(line, dot);
    });
    const lx = cx + Math.cos(mid) * 190;
    const ly = cy + Math.sin(mid) * 190;
    const anchor = Math.cos(mid) > 0.25 ? 'start' : Math.cos(mid) < -0.25 ? 'end' : 'middle';
    root.append(svg('text', { x: lx.toFixed(1), y: ly.toFixed(1), 'text-anchor': anchor, class: 'map-label' }, `${phase} (${items.length})`));
  });
  root.append(svg('circle', { cx, cy, r: 30, class: 'map-core' }), svg('text', { x: cx, y: cy + 4, 'text-anchor': 'middle', class: 'map-host' }, host.length > 14 ? `${host.slice(0, 13)}...` : host));
  $('#map-svg').replaceChildren(root);
  stagger(dots, 60);
  $('#map-table').replaceChildren(
    h('thead', {}, h('tr', {}, ...['Step', 'Request', 'Answer', 'Time'].map((t) => h('th', {}, t)))),
    h('tbody', {}, ...reqs.map((q) => h('tr', {}, h('td', {}, q.phase), h('td', { class: 'mono' }, `${q.method} ${q.path}`), h('td', {}, q.error ? q.error : String(q.status)), h('td', {}, `${q.ms} ms`)))),
  );
  box.hidden = false;
}

function reportText(s) {
  const r = s.result;
  const lines = [`FlawRadar report for ${s.host}`, `Scanned ${formatDate(s.createdAt)}`, `Grade ${r.grade}, score ${r.score} out of 100`, ''];
  const label = { fail: 'FAILED', warn: 'WARNING', pass: 'PASSED', info: 'NOTE', skip: 'NOT RUN' };
  for (const f of [...r.findings].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])) {
      lines.push(`[${label[f.status] || f.status}] ${f.title}`);
    if (f.detail) lines.push(`  What we saw: ${f.detail}`);
    if (f.why && f.status !== 'pass') lines.push(`  Why it matters: ${f.why}`);
    const cmd = reproduce(f, s.host);
    if (cmd) lines.push('  Check it yourself:', ...cmd.split('\n').map((l) => `    ${l}`));
    if (f.fix) lines.push(`  What to do: ${f.fix.text}`);
    if (f.fix?.snippets) for (const [k, v] of Object.entries(f.fix.snippets)) lines.push(`  --- ${TAB_LABELS[k] || k} ---`, ...String(v).split('\n').map((l) => `  ${l}`));
    lines.push('');
  }
  lines.push('This report is information, not a guarantee that a site is secure.');
  return lines.join('\n');
}

function exportReport() {
  const blob = new Blob([reportText(scan)], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: `flawradar-${scan.host.replace(/[^a-z0-9.-]/gi, '_')}.txt` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function renderResult(s) {
  const r = s.result;
  $('#title').textContent = `Report for ${s.host}`;
  document.title = `${s.host} - FlawRadar report`;
  const when = formatDate(s.createdAt);
  const seconds = (r.durationMs / 1000).toFixed(1);
  const allowBit = r.allow ? ' Host has a FlawRadar allow record.' : '';
  const pagesBit = r.pagesChecked > 1 ? ` ${r.pagesChecked} pages checked.` : '';
  $('#meta').textContent = `Scanned ${when}, ${seconds} seconds. Final address ${r.finalUrl}${r.ip ? ` (${r.ip})` : ''}.${s.deep ? ' Deep scan.' : ''}${pagesBit}${allowBit}`;
  $('#progress').hidden = true;
  $('#problem').hidden = true;

  if (r.blocked) {
    const who = r.blocked.vendor ? ` It looks like ${r.blocked.vendor}.` : '';
    showProblem(
      `Report for ${s.host}`,
      h('b', {}, 'The scan was blocked. '),
      `The site answered with HTTP ${r.blocked.status} instead of its home page.${who} Grading that response would describe the firewall, not your site, so no score was given. `,
      h('a', { href: '/whitelist' }, 'Add the FlawRadar addresses to your allow list'),
      ' and scan again.',
    );
    return;
  }

  $('#score').setAttribute('grade', r.grade);
  $('#score').setAttribute('score', String(r.score));
  const c = r.counts;
  $('#counts').replaceChildren(
    h('tr', {}, h('th', { scope: 'row' }, 'Failed'), h('td', {}, String(c.fail))),
    h('tr', {}, h('th', { scope: 'row' }, 'Warnings'), h('td', {}, String(c.warn))),
    h('tr', {}, h('th', { scope: 'row' }, 'Passed'), h('td', {}, String(c.pass))),
    h('tr', {}, h('th', { scope: 'row' }, 'Notes'), h('td', {}, String(c.info))),
    h('tr', {}, h('th', { scope: 'row' }, 'Not run'), h('td', {}, String(c.skip))),
  );

  const prev = $('#previous');
  if (s.previous) {
    prev.textContent = `Previous scan of this host: ${s.previous.score} (${s.previous.grade}) on ${formatDate(s.previous.createdAt)}.`;
    prev.hidden = false;
  }

  const deepSkipped = r.findings.some((f) => f.status === 'skip' && f.deep);
  $('#deep-note').hidden = !deepSkipped;
  $('#deep-link').setAttribute('href', `/verify?host=${encodeURIComponent(s.host)}`);
  const allowNote = $('#allow-note');
  if (allowNote) allowNote.hidden = !r.allow;

  const groups = new Map();
  for (const f of r.findings) {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }
  const container = $('#findings');
  container.replaceChildren();
  const categories = [...groups.keys()].sort((a, b) => CATEGORY_ORDER.indexOf(a) - CATEGORY_ORDER.indexOf(b));
  for (const category of categories) {
    const list = groups.get(category).sort(
      (a, b) =>
        STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
    );
    container.append(h('h2', {}, category), ...list.map(findingNode));
  }
  stagger([...container.querySelectorAll('.finding')], 12);

  const bundles = ['nginx', 'apache', 'express'].filter((server) =>
    r.findings.some((f) => (f.status === 'fail' || f.status === 'warn') && f.fix?.bundle?.includes(server)),
  );
  $('#downloads').hidden = bundles.length === 0;
  $('#download-links').replaceChildren(
    ...bundles.flatMap((server, i) => [
      i ? ' | ' : '',
      h('a', { href: `/api/scans/${s.id}/fix?server=${server}` }, TAB_LABELS[server]),
    ]),
  );
  plainWords(r);
  renderRisk(r);
  renderMap(r, s.host);
  $('#result').hidden = false;
  $('#delete-area').hidden = !deleteTokenFor(id);
  $('#watch-link').setAttribute('href', `/watch?host=${encodeURIComponent(s.host)}`);
}

function render(s) {
  scan = s;
  if (s.status === 'queued' || s.status === 'running') {
    $('#title').textContent = `Scanning ${s.host}`;
    $('#meta').textContent = s.status === 'queued' ? 'Waiting for a free scanner.' : 'Running.';
    renderSteps(s.progress);
    $('#progress').hidden = false;
    return false;
  }
  if (s.status === 'failed') {
    showProblem(`Report for ${s.host}`, h('b', {}, 'The scan did not finish. '), s.error || 'Unknown error.', ' ', h('a', { href: `/?url=${encodeURIComponent(s.host)}` }, 'Try again.'));
    return true;
  }
  renderResult(s);
  return true;
}

async function poll() {
  try {
    const s = await api(`/api/scans/${id}`);
    if (!render(s)) setTimeout(poll, 1200);
  } catch (err) {
    if (err.status === 404) {
      showProblem('Report not found', 'There is no report with this address. Reports are deleted after a retention period, so an old link may have expired. ', h('a', { href: '/' }, 'Start a new scan.'));
    } else {
      $('#meta').textContent = `Could not load the report (${err.message}). Retrying.`;
      setTimeout(poll, 3000);
    }
  }
}

$('#export').addEventListener('click', exportReport);

$('#print').addEventListener('click', () => {
  // Print and save-as-PDF both work from the browser's print dialog. Failed and warned findings are
  // opened first so their explanations and fixes are on paper; passed ones stay as one line each.
  const closed = [...document.querySelectorAll('details.finding[data-status="fail"]:not([open]), details.finding[data-status="warn"]:not([open])')];
  closed.forEach((d) => d.setAttribute('open', ''));
  window.addEventListener('afterprint', () => closed.forEach((d) => d.removeAttribute('open')), { once: true });
  window.print();
});

$('#delete').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  if (button.dataset.armed !== '1') {
    button.dataset.armed = '1';
    button.textContent = 'Click again to delete for good';
    setTimeout(() => {
      button.dataset.armed = '';
      button.textContent = 'Delete this report';
    }, 6000);
    return;
  }
  button.disabled = true;
  try {
    await api(`/api/scans/${id}`, { method: 'DELETE', headers: { 'X-FlawRadar-Delete': deleteTokenFor(id) || '' } });
    forgetDeleteToken(id);
    showProblem('Report deleted', 'This report was deleted from the server. Anyone with the old link now sees "not found". ', h('a', { href: '/' }, 'Start a new scan.'));
  } catch (err) {
    button.disabled = false;
    button.dataset.armed = '';
    button.textContent = 'Delete this report';
    $('#meta').textContent = err.message;
  }
});

document.querySelectorAll('.toolbar [data-filter]').forEach((b) => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.toolbar [data-filter]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    crossfade($('#findings'), () => { $('#findings').dataset.filter = b.dataset.filter; });
  });
});

$('#rescan').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    // A new scan needs the person's confirmation. If this browser has not accepted the current
    // terms, send them to the form instead of confirming on their behalf.
    const version = (await scannerInfo()).termsVersion;
    if (rememberedTerms() !== version) {
      location.assign(`/?url=${encodeURIComponent(scan.host)}`);
      return;
    }
    const next = await api('/api/scans', { method: 'POST', body: JSON.stringify({ url: scan.host, deep: scan.deep, terms: version }) });
    rememberDeleteToken(next.id, next.deleteToken);
    location.assign(`/report/${next.id}`);
  } catch (err) {
    button.disabled = false;
    $('#meta').textContent = err.message;
  }
});

poll();
