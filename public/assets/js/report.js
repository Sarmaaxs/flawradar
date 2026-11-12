import { codeTabs } from './components.js';
import { api, formatDate, h, safeHttpsUrl } from './dom.js';

const id = location.pathname.split('/').pop();
const $ = (sel) => document.querySelector(sel);

const CATEGORY_ORDER = ['Transport', 'Headers', 'Cookies', 'Content', 'DNS and mail', 'Disclosure', 'Exposure'];
const STATUS_ORDER = { fail: 0, warn: 1, pass: 2, info: 3, skip: 4 };
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const TAB_LABELS = { nginx: 'nginx', apache: 'Apache', express: 'Express', dns: 'DNS', file: 'File' };

let checks = {};
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
  $('#steps').replaceChildren(
    ...progress.map((s) =>
      h('li', {}, { running: '[ .. ]', done: '[ ok ]', failed: '[fail]' }[s.state] || '[    ]', ' ', s.name),
    ),
  );
}

function findingNode(f) {
  const meta = checks[f.id] || {};
  const body = h('div', { class: 'body' });
  if (meta.why) body.append(h('p', {}, h('b', {}, 'Why it matters. '), meta.why));
  if (f.evidence) body.append(h('pre', { class: 'evidence' }, f.evidence));
  if (f.fix) {
    body.append(h('p', {}, h('b', {}, 'How to fix. '), f.fix.text));
    if (f.fix.snippets && Object.keys(f.fix.snippets).length) body.append(codeTabs(f.fix.snippets, TAB_LABELS));
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

function renderResult(s) {
  const r = s.result;
  $('#title').textContent = `Report for ${s.host}`;
  document.title = `${s.host} - Wsec report`;
  const when = formatDate(s.createdAt);
  const seconds = (r.durationMs / 1000).toFixed(1);
  $('#meta').textContent = `Scanned ${when}, ${seconds} seconds. Final address ${r.finalUrl}${r.ip ? ` (${r.ip})` : ''}.${s.deep ? ' Deep scan.' : ''}`;
  $('#progress').hidden = true;
  $('#problem').hidden = true;

  if (r.blocked) {
    const who = r.blocked.vendor ? ` It looks like ${r.blocked.vendor}.` : '';
    showProblem(
      `Report for ${s.host}`,
      h('b', {}, 'The scan was blocked. '),
      `The site answered with HTTP ${r.blocked.status} instead of its home page.${who} Grading that response would describe the firewall, not your site, so no score was given. `,
      h('a', { href: '/whitelist' }, 'Add the Wsec addresses to your allow list'),
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

  const deepSkipped = r.findings.some((f) => f.status === 'skip' && checks[f.id]?.deep);
  $('#deep-note').hidden = !deepSkipped;
  $('#deep-link').setAttribute('href', `/verify?host=${encodeURIComponent(s.host)}`);

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
  $('#result').hidden = false;
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

document.querySelectorAll('.toolbar [data-filter]').forEach((b) => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.toolbar [data-filter]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    $('#findings').dataset.filter = b.dataset.filter;
  });
});

$('#rescan').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const next = await api('/api/scans', { method: 'POST', body: JSON.stringify({ url: scan.host, deep: scan.deep }) });
    location.assign(`/report/${next.id}`);
  } catch (err) {
    button.disabled = false;
    $('#meta').textContent = err.message;
  }
});

try {
  const { checks: list } = await api('/api/checks');
  checks = Object.fromEntries(list.map((c) => [c.id, c]));
} catch {
  /* the report still works without the explanations */
}
poll();
