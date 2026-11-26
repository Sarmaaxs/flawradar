import './components.js';
import { analyzeFiles, ruleCatalog } from '/assets/engine/analyze.js';
import { MANIFEST_FOR_CVE, skippedDir, skipReason } from '/assets/engine/paths.js';
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

// The check runs here, in the browser, with the same rule files the server uses.
// Limits are the same as the API's. Nothing in this page sends the code anywhere.
// Only package names and versions go to the server, and only to look up known vulnerabilities.
// A failed lookup becomes a note on the results instead of an error.
function engineOptions() {
  return {
    maxFileBytes: limits.maxFileKb * 1024,
    lookup: async (packages) => {
      try {
        return await api('/api/cves', { method: 'POST', body: JSON.stringify({ packages, terms: termsVersion }) });
      } catch (err) {
        return { findings: [], notices: [`Known-vulnerability lookup was skipped: ${err.message}`], checked: 0 };
      }
    },
  };
}

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
      if (zip.size > limits.maxZipMb * 1_048_576) return fail(`That zip is ${(zip.size / 1_048_576).toFixed(1)} MB. The limit is ${limits.maxZipMb} MB. Zip only the source folders, without node_modules.`);
      status(`Reading ${zip.name}...`);
      const { readZip } = await import('./zipread.js');
      const { files: inside, skipped, notices } = await readZip(zip, {
        maxEntries: limits.maxFiles * 4,
        maxFileBytes: limits.maxFileKb * 1024,
        maxTotalBytes: limits.maxTotalMb * 1_048_576,
      });
      status(`Checking ${inside.length} files...`);
      result = await analyzeFiles(inside, { skipped, notices, ...engineOptions() });
    } else {
      result = await local(files, skippedDirs);
      if (!result) return;
    }
    rememberTerms(termsVersion);
    status('');
    render(result);
  } catch (err) {
    fail(err.message || 'The check failed.');
  }
}

async function local(files, skippedDirs) {
  const left = new Set(skippedDirs);
  for (const f of files) {
    const dir = skippedDir(f.path.replace(/^\/+/, ''));
    if (dir) left.add(dir);
  }
  skippedDirs = [...left];
  const clean = (f) => f.path.replace(/^\/+/, '');
  const picked = files.filter((f) => !skipReason(clean(f)));
  const manifests = files.filter((f) => skipReason(clean(f)) && MANIFEST_FOR_CVE.test(clean(f)) && f.file.size <= limits.maxFileKb * 1024);
  const ignoredZips = files.filter((f) => /\.zip$/i.test(f.path)).length;
  if (!picked.length) {
    fail('None of those files are source code FlawRadar reads. It looks at web, script and config files such as .js, .php, .py, .html, .json and .env.');
    return null;
  }
  if (picked.length > limits.maxFiles) {
    fail(`That is ${picked.length} files. The limit is ${limits.maxFiles}. Drop only the source folders.`);
    return null;
  }

  const payload = [];
  let bytes = 0;
  let large = 0;
  let binary = 0;
  for (let i = 0; i < picked.length; i += 1) {
    const { path, file } = picked[i];
    if (i % 25 === 0) status(`Reading files... ${i} of ${picked.length}`);
    if (file.size > limits.maxFileKb * 1024) {
      large += 1;
      continue;
    }
    const content = await file.text();
    if (content.includes('\0')) {
      binary += 1;
      continue;
    }
    bytes += content.length;
    if (bytes > limits.maxTotalMb * 1_048_576) {
      fail(`That is more than ${limits.maxTotalMb} MB of source text. Drop fewer folders.`);
      return null;
    }
    payload.push({ path: path.replace(/^\/+/, ''), content });
  }

  // Lockfiles are skipped by the line rules but read for the known-vulnerability lookup.
  const skipped = [];
  for (const m of manifests) skipped.push({ path: clean(m), reason: 'generated', content: await m.file.text() });
  status(`Checking ${payload.length} files...`);
  const result = await analyzeFiles(payload, { skipped, ...engineOptions() });
  if (skippedDirs.length) result.notices.unshift(`Skipped folders: ${skippedDirs.join(', ')}. Dependencies and build output are not scanned.`);
  if (large) result.notices.push(`${large} file${large === 1 ? ' was' : 's were'} larger than ${limits.maxFileKb} KB and not read.`);
  if (binary) result.notices.push(`${binary} binary file${binary === 1 ? ' was' : 's were'} skipped.`);
  if (ignoredZips) result.notices.push('Zip files dropped together with other files are ignored. Drop a single .zip on its own to scan it.');
  return result;
}

function findingNode(f) {
  if (f.cve) {
    const params = new URLSearchParams({ id: f.cve, package: f.package || '', version: f.version || '', ecosystem: f.ecosystem || '', severity: f.severity || 'unknown', file: f.file || '', line: String(f.line || 1), summary: f.why || '', fix: f.fix || '', details: f.advisoryDetails || '', refs: JSON.stringify(f.advisoryReferences || []), ranges: JSON.stringify(f.affectedRanges || []) });
    return h('article', { class: 'finding cve-finding', 'data-severity': f.severity },
      h('a', { class: 'cve-finding-link', href: '/cve?' + params.toString() },
        h('w-status', { value: COLOUR[f.severity], label: f.severity }),
        h('span', {}, h('span', { class: 'title' }, f.title),
          h('span', { class: 'conf' }, 'OSV dependency match · high confidence'),
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

function showRules() {
  const rules = ruleCatalog();
  $('#limits').textContent = `Up to ${limits.maxFiles} files, ${limits.maxFileKb} KB per file, ${limits.maxTotalMb} MB of text in total, or a zip up to ${limits.maxZipMb} MB. Folders such as node_modules, .git, vendor, dist and build are skipped.`;
  $('#rule-count').textContent = `${rules.length} rules`;
  $('#rules').replaceChildren(
    h('thead', {}, h('tr', {}, h('th', {}, 'Rule'), h('th', {}, 'Severity'), h('th', {}, 'Applies to'))),
    h('tbody', {}, ...rules.map((r) => h('tr', {}, h('td', {}, r.title), h('td', {}, r.severity), h('td', {}, r.applies)))),
  );
}
showRules();
