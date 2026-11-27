import './components.js';
import { crossfade, stagger } from './motion.js';
import { api, h, forgetTerms, rememberTerms, rememberedTerms, scannerInfo } from './dom.js';

const $ = (sel) => document.querySelector(sel);

let termsVersion = null;
try {
  termsVersion = (await scannerInfo()).termsVersion;
  if (rememberedTerms() === termsVersion) $('#terms').checked = true;
  else if (rememberedTerms()) forgetTerms();
} catch {
  /* the server will say so when the upload is sent */
}
$('#terms').addEventListener('change', () => $('#consent-box').classList.remove('attention'));

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const COLOUR = { critical: 'fail', high: 'fail', medium: 'warn', low: 'info' };

// Files are selected in the browser and analyzed by the server in memory.
// The server-side rule implementation is not shipped to the browser.
// Dependency identifiers may be sent to public advisory databases for matching.
const limits = { maxFiles: 3000, maxFileKb: 512, maxZipMb: 10, maxTotalMb: 30 };

function status(message) {
  const el = $('#status');
  el.textContent = message || '';
  el.hidden = !message;
}

function fail(message) {
  const el = $('#error');
  el.textContent = message;
  el.hidden = false;
  status('');
}

async function run(files, skippedDirs) {
  $('#error').hidden = true;
  $('#result').hidden = true;
  if (!$('#terms').checked) {
    $('#consent-box').classList.add('attention');
    $('#terms').focus();
    return fail('Please confirm that you may check this code and accept the terms first, then drop it again.');
  }
  if (!files.length) return fail('No files were found. Drop a folder, some files, or a .zip.');
  const zip = files.length === 1 && /\.zip$/i.test(files[0].path) ? files[0].file : null;
  try {
    let result;
    if (zip) {
      if (zip.size > limits.maxZipMb * 1_048_576) return fail(`That zip is ${(zip.size / 1_048_576).toFixed(1)} MB. The limit is ${limits.maxZipMb} MB.`);
      status(`Uploading ${zip.name} for in-memory analysis...`);
      result = await api('/api/source/zip', { method: 'POST', body: zip, headers: { 'Content-Type': 'application/zip', 'X-FlawRadar-Terms': termsVersion } });
    } else {
      const skipped = new Set(skippedDirs || []);
      const skipNames = new Set(['node_modules', '.git', '.svn', '.hg', 'vendor', 'dist', 'build', '.next', '.nuxt', '.cache', '__pycache__', 'venv', '.venv', 'bower_components', 'coverage', '.idea', '.vscode', 'target']);
      const picked = files.filter((f) => !f.path.split('/').some((part) => skipNames.has(part)));
      if (picked.length > limits.maxFiles) return fail(`That is ${picked.length} files. The limit is ${limits.maxFiles}.`);
      const payload = [];
      let bytes = 0; let large = 0; let binary = 0;
      for (let i = 0; i < picked.length; i += 1) {
        const item = picked[i];
        if (i % 25 === 0) status(`Reading selected files... ${i} of ${picked.length}`);
        if (item.file.size > limits.maxFileKb * 1024) { large += 1; continue; }
        const content = await item.file.text();
        if (content.includes('\0')) { binary += 1; continue; }
        bytes += content.length;
        if (bytes > limits.maxTotalMb * 1_048_576) return fail(`That is more than ${limits.maxTotalMb} MB of source text.`);
        payload.push({ path: item.path.replace(/^\/+/, ''), content });
      }
      if (!payload.length) return fail('No readable source or dependency files were found.');
      status(`Sending ${payload.length} selected files for in-memory analysis...`);
      result = await api('/api/source', { method: 'POST', body: JSON.stringify({ files: payload, terms: termsVersion }) });
      if (skipped.size) result.notices.unshift(`Skipped folders: ${[...skipped].join(', ')}.`);
      if (large) result.notices.push(`${large} oversized files were skipped.`);
      if (binary) result.notices.push(`${binary} binary files were skipped.`);
    }
    rememberTerms(termsVersion);
    status('');
    render(result);
  } catch (err) {
    fail(err.message || 'The check failed.');
  }
}

function findingNode(f) {
  if (f.cve) {
    const params = new URLSearchParams({ id: f.cve, osv: f.osvId || '', package: f.package || '', version: f.version || '', ecosystem: f.ecosystem || '', severity: f.severity || 'unknown', file: f.file || '', line: String(f.line || 1), summary: f.why || '', fix: f.fix || '', details: f.advisoryDetails || '', refs: JSON.stringify(f.advisoryReferences || []), ranges: JSON.stringify(f.affectedRanges || []), aliases: JSON.stringify(f.aliases || []), cvss: f.cvss || '', cvssBase: String(f.cvssBaseScore ?? ''), epss: JSON.stringify(f.epss || null), kev: JSON.stringify(f.kev || null), published: f.published || '', modified: f.modified || '', affectedPackages: JSON.stringify(f.affectedPackages || []) });
    return h('article', { class: 'finding cve-finding', 'data-severity': f.severity },
      h('a', { class: 'cve-finding-link', href: '/cve?' + params.toString() },
        h('w-status', { value: COLOUR[f.severity], label: f.severity }),
        h('span', {}, h('span', { class: 'title' }, f.title),
          h('span', { class: 'conf' }, `OSV match${f.kev ? ' · CISA KEV' : ''}${f.epss?.score ? ` · EPSS ${(f.epss.score * 100).toFixed(1)}%` : ''}`),
          h('span', { class: 'brief where' }, f.file + ':' + f.line),
          h('span', { class: 'cve-open' }, 'Open vulnerability analysis →'))));
  }
  const body = h('div', { class: 'body' },
    h('p', { class: 'where' }, f.file + ':' + f.line),
    h('pre', { class: 'snippet' }, f.snippet),
    h('p', {}, h('b', {}, 'Why it matters. '), f.why),
    h('p', {}, h('b', {}, 'How to fix. '), f.fix));
  return h('details', { class: 'finding', 'data-severity': f.severity, open: f.severity === 'critical' },
    h('summary', {}, h('w-status', { value: COLOUR[f.severity], label: f.severity }),
      h('span', {}, h('span', { class: 'title' }, f.title),
        h('span', { class: 'conf' }, f.confidence + ' confidence'),
        h('span', { class: 'brief where' }, f.file + ':' + f.line))),
    body);
}

function render(r) {
  const s = r.summary;
  const total = SEVERITIES.reduce((n, k) => n + s[k], 0);
  $('#counts').replaceChildren(
    ...SEVERITIES.map((k) => h('tr', {}, h('th', { scope: 'row' }, k[0].toUpperCase() + k.slice(1)), h('td', {}, String(s[k])))),
  );
  const st = r.stats;
  const pkgBit = st.packagesChecked
    ? `, ${st.packagesChecked} package version${st.packagesChecked === 1 ? '' : 's'} checked for known CVEs`
    : '';
  $('#stats').textContent = `${st.filesScanned} files and ${st.lines.toLocaleString('en-US')} lines read, ${st.filesSkipped} skipped, ${st.rules} line rules plus file checks${pkgBit}, ${(st.durationMs / 1000).toFixed(1)} seconds.`;
  $('#notices').replaceChildren(...r.notices.map((n) => h('p', { class: 'alert note' }, n)));

  const list = $('#findings');
  if (!total) {
    list.replaceChildren(h('p', { class: 'notice' }, 'No findings. That means none of the patterns matched. It does not mean the code is secure.'));
  } else {
    list.replaceChildren(...r.findings.map(findingNode));
  }
  stagger([...list.querySelectorAll('.finding')], 12);
  list.dataset.filter = 'all';
  document.querySelectorAll('.toolbar [data-filter]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.filter === 'all')));
  $('#result').hidden = false;
  $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.querySelectorAll('.toolbar [data-filter]').forEach((b) => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.toolbar [data-filter]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    crossfade($('#findings'), () => { $('#findings').dataset.filter = b.dataset.filter; });
  });
});

$('#drop').addEventListener('w-files', (e) => run(e.detail.files, e.detail.skippedDirs));

$('#limits').textContent = `Up to ${limits.maxFiles} files, ${limits.maxFileKb} KB per file, ${limits.maxTotalMb} MB of text in total, or a zip up to ${limits.maxZipMb} MB. Common dependency and build folders are skipped.`;
