import './components.js';
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

// Mirror of the server's limits. The server enforces them again.
let limits = { maxFiles: 3000, maxFileKb: 512, maxZipMb: 10, maxTotalMb: 30 };
const SKIP_FILE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Pipfile\.lock|poetry\.lock|Gemfile\.lock|\.DS_Store)$|\.min\.(?:js|css)$|\.map$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '.hg', 'vendor', 'dist', 'build', '.next', '.nuxt', '.cache', '__pycache__', 'venv', '.venv', 'bower_components', 'coverage', '.idea', '.vscode', 'target']);
const TEXT_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'py', 'php', 'phtml', 'inc', 'html', 'htm', 'ejs', 'hbs', 'twig', 'json', 'yml', 'yaml', 'toml', 'ini', 'conf', 'cfg', 'config', 'env', 'properties', 'txt', 'sh', 'rb', 'java', 'go', 'cs', 'htaccess']);

function wanted(path) {
  const parts = path.split('/');
  if (parts.slice(0, -1).some((p) => SKIP_DIRS.has(p))) return false;
  if (SKIP_FILE.test(path)) return false;
  const name = parts[parts.length - 1].toLowerCase();
  if (name.startsWith('.env') || name.startsWith('dockerfile') || name === '.htaccess') return true;
  const dot = name.lastIndexOf('.');
  return TEXT_EXT.has(dot > 0 ? name.slice(dot + 1) : dot === 0 ? name.slice(1) : '');
}

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
    return fail('Please confirm that you may upload this code and accept the terms first, then drop it again.');
  }
  if (!files.length) return fail('No files were found. Drop a folder, some files, or a .zip.');

  const zip = files.length === 1 && /\.zip$/i.test(files[0].path) ? files[0].file : null;
  try {
    let result;
    if (zip) {
      if (zip.size > limits.maxZipMb * 1_048_576) return fail(`That zip is ${(zip.size / 1_048_576).toFixed(1)} MB. The limit is ${limits.maxZipMb} MB. Zip only the source folders, without node_modules.`);
      status(`Uploading ${zip.name}...`);
      result = await api('/api/source/zip', {
        method: 'POST',
        body: zip,
        headers: { 'Content-Type': 'application/zip', 'X-Wsec-Terms': termsVersion || '' },
      });
    } else {
      result = await upload(files, skippedDirs);
      if (!result) return;
    }
    rememberTerms(termsVersion);
    status('');
    render(result);
  } catch (err) {
    fail(err.message);
  }
}

async function upload(files, skippedDirs) {
  // A folder chosen with the picker arrives as a flat list, so note which folders were left out.
  const left = new Set(skippedDirs);
  for (const f of files) {
    const dir = f.path.split('/').slice(0, -1).find((p) => SKIP_DIRS.has(p));
    if (dir) left.add(dir);
  }
  skippedDirs = [...left];
  const picked = files.filter((f) => wanted(f.path.replace(/^\/+/, '')));
  const ignoredZips = files.filter((f) => /\.zip$/i.test(f.path)).length;
  if (!picked.length) {
    fail('None of those files are source code Wsec reads. It looks at web, script and config files such as .js, .php, .py, .html, .json and .env.');
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

  status(`Uploading ${payload.length} files...`);
  const result = await api('/api/source', { method: 'POST', body: JSON.stringify({ files: payload, terms: termsVersion }) });

  if (skippedDirs.length) result.notices.unshift(`Skipped folders: ${skippedDirs.join(', ')}. Dependencies and build output are not scanned.`);
  if (large) result.notices.push(`${large} file${large === 1 ? ' was' : 's were'} larger than ${limits.maxFileKb} KB and not read.`);
  if (binary) result.notices.push(`${binary} binary file${binary === 1 ? ' was' : 's were'} skipped.`);
  if (ignoredZips) result.notices.push('Zip files dropped together with other files are ignored. Drop a single .zip on its own to scan it.');
  return result;
}

function findingNode(f) {
  const body = h(
    'div',
    { class: 'body' },
    h('p', { class: 'where' }, `${f.file}:${f.line}`),
    h('pre', { class: 'snippet' }, f.snippet),
    h('p', {}, h('b', {}, 'Why it matters. '), f.why),
    h('p', {}, h('b', {}, 'How to fix. '), f.fix),
  );
  return h(
    'details',
    { class: 'finding', 'data-severity': f.severity, open: f.severity === 'critical' },
    h(
      'summary',
      {},
      h('w-status', { value: COLOUR[f.severity], label: f.severity }),
      h(
        'span',
        {},
        h('span', { class: 'title' }, f.title),
        h('span', { class: 'conf' }, `${f.confidence} confidence`),
        h('span', { class: 'brief where' }, `${f.file}:${f.line}`),
      ),
    ),
    body,
  );
}

function render(r) {
  const s = r.summary;
  const total = SEVERITIES.reduce((n, k) => n + s[k], 0);
  $('#counts').replaceChildren(
    ...SEVERITIES.map((k) => h('tr', {}, h('th', { scope: 'row' }, k[0].toUpperCase() + k.slice(1)), h('td', {}, String(s[k])))),
  );
  const st = r.stats;
  $('#stats').textContent = `${st.filesScanned} files and ${st.lines.toLocaleString('en-US')} lines read, ${st.filesSkipped} skipped, ${st.rules} line rules plus file checks, ${(st.durationMs / 1000).toFixed(1)} seconds.`;
  $('#notices').replaceChildren(...r.notices.map((n) => h('p', { class: 'alert note' }, n)));

  const list = $('#findings');
  if (!total) {
    list.replaceChildren(h('p', { class: 'notice' }, 'No findings. That means none of the patterns matched. It does not mean the code is secure.'));
  } else {
    list.replaceChildren(...r.findings.map(findingNode));
  }
  list.dataset.filter = 'all';
  document.querySelectorAll('.toolbar [data-filter]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.filter === 'all')));
  $('#result').hidden = false;
  $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.querySelectorAll('.toolbar [data-filter]').forEach((b) => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.toolbar [data-filter]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    $('#findings').dataset.filter = b.dataset.filter;
  });
});

$('#drop').addEventListener('w-files', (e) => run(e.detail.files, e.detail.skippedDirs));

async function loadRules() {
  try {
    const data = await api('/api/source/rules');
    limits = data.limits;
    $('#limits').textContent = `Up to ${limits.maxFiles} files, ${limits.maxFileKb} KB per file, ${limits.maxTotalMb} MB of text in total, or a zip up to ${limits.maxZipMb} MB. Folders such as node_modules, .git, vendor, dist and build are skipped.`;
    $('#rule-count').textContent = `${data.rules.length} rules`;
    $('#rules').replaceChildren(
      h('thead', {}, h('tr', {}, h('th', {}, 'Rule'), h('th', {}, 'Severity'), h('th', {}, 'Applies to'))),
      h('tbody', {}, ...data.rules.map((r) => h('tr', {}, h('td', {}, r.title), h('td', {}, r.severity), h('td', {}, r.applies)))),
    );
  } catch (err) {
    $('#limits').textContent = `Could not load the rule list (${err.message}).`;
  }
}
loadRules();