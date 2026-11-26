/**
 * Look up known vulnerabilities for dependencies found in the upload.
 * Uses the public OSV API (https://osv.dev). Results are never stored.
 *
 * Supported manifests (best → weakest):
 *   - package-lock.json (v1 / v2 / v3)
 *   - package.json (only when no lockfile; versions are ranges, less precise)
 *   - requirements.txt (name==version lines)
 */

import { baseName } from './paths.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const MAX_PACKAGES = 1200; // keep the request and response small
const BATCH_SIZE = 100;
const REQUEST_TIMEOUT_MS = 12_000;
const DETAIL_CONCURRENCY = 8;
const MAX_CVE_FINDINGS = 400;

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const EPSS_URL = 'https://api.first.org/data/v1/epss';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
let kevCache = { at: 0, entries: new Map() };

async function intelligenceSignals(cveIds, doFetch) {
  const epss = new Map(); const kev = new Map(); const ids = [...new Set(cveIds.filter((id) => /^CVE-\d{4}-\d{4,}$/i.test(id)))];
  if (!ids.length) return { epss, kev, notices: [] };
  const notices = [];
  try {
    for (let i = 0; i < ids.length; i += 100) {
      const batch = ids.slice(i, i + 100);
      const url = `${EPSS_URL}?cve=${encodeURIComponent(batch.join(','))}`;
      const res = await doFetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (!res.ok) throw new Error(`EPSS HTTP ${res.status}`);
      const body = await res.json();
      for (const item of body.data || []) epss.set(item.cve, { score: Number(item.epss), percentile: Number(item.percentile), date: item.date || null });
    }
  } catch { notices.push('EPSS exploitation-likelihood data was unavailable; CVSS and advisory severity are still shown.'); }
  try {
    const useSharedCache = doFetch === globalThis.fetch;
    let entries = useSharedCache ? kevCache.entries : null;
    if (!useSharedCache || kevCache.at === 0 || Date.now() - kevCache.at > 6 * 60 * 60 * 1000) {
      const res = await doFetch(KEV_URL, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
      const body = await res.json();
      entries = new Map();
      for (const item of body.vulnerabilities || []) if (item.cveID) entries.set(item.cveID, item);
      if (useSharedCache) kevCache = { at: Date.now(), entries };
    }
    for (const id of ids) if (entries.has(id)) {
      const item = entries.get(id);
      kev.set(id, { dateAdded: item.dateAdded || null, dueDate: item.dueDate || null, requiredAction: String(item.requiredAction || '').slice(0, 800), ransomware: item.knownRansomwareCampaignUse || 'Unknown', vendor: item.vendorProject || '', product: item.product || '' });
    }
  } catch { notices.push('CISA Known Exploited Vulnerabilities status was unavailable; no KEV status is assumed.'); }
  return { epss, kev, notices };
}

/** @typedef {{ name: string, version: string, ecosystem: string, file: string, line: number }} Pkg */

/**
 * Collect packages from the readable files. Prefer lockfiles over package.json.
 * @param {{ path: string, content: string }[]} files
 * @returns {{ packages: Pkg[], notices: string[] }}
 */
export function collectPackages(files) {
  const packages = [];
  const notices = [];
  const seen = new Set(); // ecosystem|name|version

  const byName = new Map();
  for (const f of files) byName.set(baseName(f.path).toLowerCase(), f);

  // Prefer lockfiles: one per directory is enough
  const lockfiles = files.filter((f) => /(?:^|\/)package-lock\.json$/i.test(f.path));
  const hasNpmLock = lockfiles.length > 0;

  for (const f of lockfiles) {
    try {
      for (const pkg of parsePackageLock(f.path, f.content)) {
        const key = `${pkg.ecosystem}|${pkg.name}|${pkg.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        packages.push(pkg);
      }
    } catch {
      notices.push(`Could not parse ${f.path} for vulnerability lookup.`);
    }
  }

  // package.json only when no lockfile was present at all
  if (!hasNpmLock) {
    for (const f of files) {
      if (baseName(f.path).toLowerCase() !== 'package.json') continue;
      try {
        for (const pkg of parsePackageJson(f.path, f.content)) {
          const key = `${pkg.ecosystem}|${pkg.name}|${pkg.version}`;
          if (seen.has(key)) continue;
          seen.add(key);
          packages.push(pkg);
        }
      } catch {
        /* ignore broken package.json */
      }
    }
    if (packages.some((p) => p.ecosystem === 'npm')) {
      notices.push(
        'No package-lock.json found. CVE checks used version ranges from package.json and may miss or over-report issues. Commit a lockfile for accurate results.',
      );
    }
  }

  for (const f of files) {
    if (!/^requirements[\w.-]*\.txt$/i.test(baseName(f.path))) continue;
    try {
      for (const pkg of parseRequirements(f.path, f.content)) {
        const key = `${pkg.ecosystem}|${pkg.name}|${pkg.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        packages.push(pkg);
      }
    } catch {
      notices.push(`Could not parse ${f.path} for vulnerability lookup.`);
    }
  }

  // Additional ecosystems. Each parser emits exact resolved versions where lockfiles provide them.
  for (const f of files) {
    const name = baseName(f.path).toLowerCase();
    let parsed = [];
    try {
      if (name === 'go.sum' || name === 'go.mod') parsed = parseGo(f.path, f.content);
      else if (name === 'cargo.lock') parsed = parseCargo(f.path, f.content);
      else if (name === 'composer.lock') parsed = parseComposer(f.path, f.content);
      else if (name === 'gemfile.lock') parsed = parseGemfile(f.path, f.content);
      else if (name === 'pom.xml' || name.endsWith('.csproj') || name === 'packages.config') parsed = parseXmlPackages(f.path, f.content);
      else if (name === 'packages.lock.json') parsed = parseNugetLock(f.path, f.content);
      else if (name === 'poetry.lock' || name === 'pipfile.lock') parsed = parsePythonLock(f.path, f.content);
    } catch { notices.push(`Could not parse ${f.path} for vulnerability lookup.`); }
    for (const pkg of parsed) {
      const key = `${pkg.ecosystem}|${pkg.name}|${pkg.version}`;
      if (seen.has(key)) continue;
      seen.add(key); packages.push(pkg);
    }
  }

  if (packages.length > MAX_PACKAGES) {
    notices.push(
      `Only the first ${MAX_PACKAGES} of ${packages.length} packages were checked for known vulnerabilities.`,
    );
    packages.length = MAX_PACKAGES;
  }

  return { packages, notices };
}

/**
 * Query OSV and turn hits into findings in the same shape as the rest of the scanner.
 * querybatch only returns vuln ids; we then hydrate each id for severity and fix info.
 * @param {Pkg[]} packages
 * @param {{ fetch?: typeof fetch }} [opts]
 * @returns {Promise<{ findings: object[], notices: string[], checked: number }>}
 */
export async function lookupCves(packages, opts = {}) {
  const findings = [];
  const notices = [];
  if (!packages.length) return { findings, notices, checked: 0 };

  const doFetch = opts.fetch || globalThis.fetch;
  let checked = 0;

  // vulnId → list of packages affected
  /** @type {Map<string, Pkg[]>} */
  const hits = new Map();

  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const queries = batch.map((p) => ({
      package: { name: p.name, ecosystem: p.ecosystem },
      version: p.version,
    }));

    let results;
    try {
      const res = await doFetch(OSV_BATCH_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'User-Agent': 'FlawRadar-Scanner/0.1 (+https://flawradar.pro.et)',
        },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!res.ok) {
        notices.push(`Vulnerability database returned HTTP ${res.status}. CVE checks were skipped for this batch.`);
        continue;
      }
      const body = await res.json();
      results = body.results || [];
    } catch (err) {
      const msg = err.name === 'TimeoutError' || err.name === 'AbortError'
        ? 'Vulnerability database timed out.'
        : 'Could not reach the vulnerability database.';
      notices.push(`${msg} CVE checks were skipped for this batch.`);
      continue;
    }

    checked += batch.length;

    for (let j = 0; j < batch.length; j += 1) {
      const pkg = batch[j];
      for (const v of results[j]?.vulns || []) {
        if (!v?.id) continue;
        if (!hits.has(v.id)) hits.set(v.id, []);
        hits.get(v.id).push(pkg);
      }
    }
  }

  // Hydrate vuln details (severity, aliases, fixed versions)
  const ids = [...hits.keys()];
  const details = new Map();
  for (let i = 0; i < ids.length; i += DETAIL_CONCURRENCY) {
    const slice = ids.slice(i, i + DETAIL_CONCURRENCY);
    await Promise.all(
      slice.map(async (id) => {
        try {
          const res = await doFetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
            headers: {
              Accept: 'application/json',
              'User-Agent': 'FlawRadar-Scanner/0.1 (+https://flawradar.pro.et)',
            },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          });
          if (!res.ok) return;
          details.set(id, await res.json());
        } catch {
          // keep the sparse entry; severity will fall back to medium
        }
      }),
    );
  }

  const signalIds = [];
  for (const vuln of details.values()) signalIds.push(...(vuln.aliases || []).filter((a) => /^CVE-/i.test(a)));
  const signals = await intelligenceSignals(signalIds, doFetch);
  for (const [id, pkgs] of hits) {
    const vuln = details.get(id) || { id };
    for (const pkg of pkgs) {
      const finding = vulnToFinding(pkg, vuln);
      if (!finding) continue;
      const epss = signals.epss.get(finding.cve) || null;
      const kev = signals.kev.get(finding.cve) || null;
      finding.epss = epss;
      finding.kev = kev;
      findings.push(finding);
    }
  }

  // Severity remains primary; known in-the-wild exploitation and EPSS break ties.
  findings.sort((a, b) =>
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    Number(Boolean(b.kev)) - Number(Boolean(a.kev)) ||
    (b.epss?.score || 0) - (a.epss?.score || 0) ||
    a.file.localeCompare(b.file) || a.title.localeCompare(b.title));

  if (findings.length > MAX_CVE_FINDINGS) {
    findings.length = MAX_CVE_FINDINGS;
    notices.push(`Only the ${MAX_CVE_FINDINGS} highest-severity known vulnerabilities are shown.`);
  }

  return { findings, notices: [...notices, ...signals.notices], checked };
}

/**
 * Run package collection + OSV lookup. Safe to call even when offline.
 * @param {{ path: string, content: string }[]} files
 * @param {{ fetch?: typeof fetch }} [opts]
 */
export async function runCveChecks(files, opts = {}) {
  const { packages, notices: collectNotices } = collectPackages(files);
  if (!packages.length) {
    return { findings: [], notices: collectNotices, checked: 0, packages: 0 };
  }
  const lookup = opts.lookup || lookupCves; // the browser passes a function that asks the server
  const { findings, notices: lookupNotices, checked } = await lookup(packages, opts);
  return {
    findings,
    notices: [...collectNotices, ...lookupNotices],
    checked,
    packages: packages.length,
  };
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

function parsePackageLock(path, content) {
  const lock = JSON.parse(content);
  const out = [];
  const version = lock.lockfileVersion || 1;

  if (version >= 2 && lock.packages && typeof lock.packages === 'object') {
    for (const [key, info] of Object.entries(lock.packages)) {
      if (!key || key === '') continue; // root
      if (!info || typeof info !== 'object') continue;
      if (info.link || info.extraneous) continue;
      const name = packageNameFromLockKey(key, info);
      const ver = info.version;
      if (!name || !ver || typeof ver !== 'string') continue;
      if (!/^\d/.test(ver)) continue; // skip non-semver (git, file, etc.)
      out.push({
        name,
        version: ver,
        ecosystem: 'npm',
        file: path,
        line: 1,
      });
    }
    return out;
  }

  // lockfileVersion 1
  function walk(deps, parentPath) {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, info] of Object.entries(deps)) {
      if (!info || typeof info !== 'object') continue;
      const ver = info.version;
      if (ver && typeof ver === 'string' && /^\d/.test(ver)) {
        out.push({ name, version: ver, ecosystem: 'npm', file: path, line: 1 });
      }
      if (info.dependencies) walk(info.dependencies, `${parentPath}/${name}`);
    }
  }
  walk(lock.dependencies, '');
  return out;
}

function packageNameFromLockKey(key, info) {
  if (info.name && typeof info.name === 'string') return info.name;
  // "node_modules/lodash" or "node_modules/@scope/pkg"
  const m = key.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
  return m ? m[1] : null;
}

function parsePackageJson(path, content) {
  const pkg = JSON.parse(content);
  const out = [];
  const lineOf = (text) => {
    const i = content.indexOf(`"${text}"`);
    return i < 0 ? 1 : content.slice(0, i).split('\n').length;
  };

  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(pkg[group] || {})) {
      if (typeof range !== 'string') continue;
      const version = rangeToApproxVersion(range);
      if (!version) continue;
      out.push({
        name,
        version,
        ecosystem: 'npm',
        file: path,
        line: lineOf(name),
      });
    }
  }
  return out;
}

/** Best-effort: turn "^1.2.3" / "~1.2.3" / "1.2.3" into a concrete version OSV can query. */
function rangeToApproxVersion(range) {
  const r = range.trim();
  if (!r || r === '*' || r === 'latest' || r === 'x') return null;
  if (/^(?:https?:|git\+|git:|file:|workspace:|npm:)/i.test(r)) return null;
  // exact
  if (/^\d+\.\d+\.\d+/.test(r)) return r.match(/^\d+\.\d+\.\d+[\w.-]*/)?.[0] || null;
  // ^1.2.3 or ~1.2.3 or >=1.2.3 <2
  const m = r.match(/(\d+\.\d+\.\d+[\w.-]*)/);
  return m ? m[1] : null;
}

function parseRequirements(path, content) {
  const out = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    let text = lines[i].trim();
    if (!text || text.startsWith('#') || text.startsWith('-')) continue;
    // strip environment markers: pkg==1.0; python_version >= "3"
    text = text.split(';')[0].trim();
    // name==1.2.3 or name===1.2.3 or name@1.2.3
    const m = text.match(/^([A-Za-z0-9_.-]+)\s*(?:==|===|@)\s*([0-9][^\s\\;]+)/);
    if (!m) continue;
    const name = normalizePyName(m[1]);
    const version = m[2].replace(/\\$/g, '').trim();
    if (!name || !version) continue;
    out.push({
      name,
      version,
      ecosystem: 'PyPI',
      file: path,
      line: i + 1,
    });
  }
  return out;
}

function normalizePyName(name) {
  // PEP 503: lowercase, _ and . become -
  return name.toLowerCase().replace(/[._]/g, '-');
}

function parseGo(path, content) {
  const out = [];
  for (const [i, line] of content.split('\n').entries()) {
    let t = line.trim();
    if (!t || t.startsWith('//') || t.startsWith('module ') || t.startsWith('go ') || t === 'require (' || t === ')') continue;
    t = t.replace(/^require\s+/, '');
    const m = t.match(/^([^\s]+)\s+(v?\d+\.\d+\.\d+(?:[-+][^\s]+)?)(?:\s+\/\/.*)?$/);
    if (!m || m[1].startsWith('replace')) continue;
    let version = m[2].replace(/\+incompatible$/, '').replace(/\/go\.mod$/, '');
    if (version.startsWith('v')) version = version.slice(1);
    if (version.includes('/')) continue;
    out.push({ name: m[1], version, ecosystem: 'Go', file: path, line: i + 1 });
  }
  return out;
}

function parseCargo(path, content) {
  const out = []; let block = ''; let start = 1;
  const flush = () => {
    const name = block.match(/^name\s*=\s*["']([^"']+)["']/m)?.[1];
    const version = block.match(/^version\s*=\s*["']([^"']+)["']/m)?.[1];
    if (name && version) out.push({ name, version, ecosystem: 'crates.io', file: path, line: start });
  };
  for (const [i, line] of content.split('\n').entries()) { if (line.trim() === '[[package]]') { if (block) flush(); block = ''; start = i + 1; } else block += line + '\n'; }
  if (block) flush(); return out;
}

function parseComposer(path, content) {
  const doc = JSON.parse(content); const out = [];
  for (const p of [...(doc.packages || []), ...(doc['packages-dev'] || [])]) if (p.name && p.version) out.push({ name: p.name, version: String(p.version).replace(/^v/, ''), ecosystem: 'Packagist', file: path, line: 1 });
  return out;
}

function parseGemfile(path, content) {
  const out = []; let inSpecs = false;
  for (const [i, line] of content.split('\n').entries()) {
    if (/^  specs:/.test(line)) { inSpecs = true; continue; }
    if (inSpecs && /^  [a-zA-Z]/.test(line)) inSpecs = false;
    if (!inSpecs) continue;
    const m = line.match(/^    ([A-Za-z0-9_.-]+) \(([^)]+)\)/);
    if (m) out.push({ name: m[1], version: m[2].split(' ')[0], ecosystem: 'RubyGems', file: path, line: i + 1 });
  }
  return out;
}

function parseXmlPackages(path, content) {
  const out = []; const re = /<PackageReference\b[^>]*Include=["']([^"']+)["'][^>]*Version=["']([^"']+)["'][^>]*\/?>|<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/gi;
  let m; while ((m = re.exec(content))) {
    if (m[1] && m[2] && !m[2].includes('$')) out.push({ name: m[1], version: m[2], ecosystem: 'NuGet', file: path, line: content.slice(0,m.index).split('\n').length });
    else if (m[3] && m[4] && m[5] && !m[5].includes('$')) out.push({ name: `${m[3]}:${m[4]}`, version: m[5], ecosystem: 'Maven', file: path, line: content.slice(0,m.index).split('\n').length });
  }
  const old = /<package\s+id=["']([^"']+)["']\s+version=["']([^"']+)["']/gi;
  while ((m = old.exec(content))) out.push({ name: m[1], version: m[2], ecosystem: 'NuGet', file: path, line: content.slice(0,m.index).split('\n').length });
  return out;
}

function parseNugetLock(path, content) {
  const doc = JSON.parse(content); const out = [];
  for (const [framework, deps] of Object.entries(doc.dependencies || {})) for (const [name, meta] of Object.entries(deps || {})) {
    const version = meta?.resolved; if (version) out.push({ name, version: String(version), ecosystem: 'NuGet', file: path, line: 1 });
  }
  return out;
}

function parsePythonLock(path, content) {
  const out = [];
  if (baseName(path).toLowerCase() === 'poetry.lock') {
    let name = null, version = null, line = 1;
    for (const [i, row] of content.split('\n').entries()) {
      if (row.trim() === '[[package]]') { if (name && version) out.push({ name: normalizePyName(name), version, ecosystem: 'PyPI', file: path, line }); name = null; version = null; line = i + 1; }
      name ||= row.match(/^name\s*=\s*["']([^"']+)["']/)?.[1] || null;
      version ||= row.match(/^version\s*=\s*["']([^"']+)["']/)?.[1] || null;
    }
    if (name && version) out.push({ name: normalizePyName(name), version, ecosystem: 'PyPI', file: path, line });
  } else {
    try { const doc = JSON.parse(content); for (const [name, meta] of Object.entries(doc.default || {})) { const v = meta?.version?.replace(/^==/, ''); if (v) out.push({ name: normalizePyName(name), version: v, ecosystem: 'PyPI', file: path, line: 1 }); } } catch {}
  }
  return out;
}

// ---------------------------------------------------------------------------
// OSV → finding
// ---------------------------------------------------------------------------

function vulnToFinding(pkg, vuln) {
  if (!vuln || !vuln.id) return null;
  const severity = scoreSeverity(vuln);
  const summary = (vuln.summary || vuln.details || '').split('\n')[0].trim().slice(0, 200);
  const aliases = (vuln.aliases || []).filter((a) => /^CVE-/.test(a));
  const cveLabel = aliases[0] || vuln.id;
  const title = `${cveLabel} in ${pkg.name}@${pkg.version}`;

  const whyParts = [];
  if (summary) whyParts.push(summary);
  whyParts.push(`Known vulnerability in ${pkg.ecosystem} package ${pkg.name} version ${pkg.version}.`);
  if (aliases.length) whyParts.push(`Also tracked as ${aliases.slice(0, 3).join(', ')}.`);

  const fix = buildFix(pkg, vuln);

  return {
    ruleId: 'cve-known',
    title,
    severity,
    confidence: 'high',
    file: pkg.file,
    line: pkg.line || 1,
    snippet: `${pkg.name}@${pkg.version}`,
    why: whyParts.join(' '),
    fix,
    // extra fields the UI can ignore
    cve: cveLabel,
    osvId: vuln.id,
    package: pkg.name,
    version: pkg.version,
    ecosystem: pkg.ecosystem,
    advisoryDetails: String(vuln.details || '').slice(0, 1800),
    advisoryReferences: (vuln.references || []).filter((r) => r && /^https:\/\//i.test(r.url || '')).slice(0, 4).map((r) => ({ type: String(r.type || 'WEB').slice(0, 20), url: r.url })),
    affectedRanges: (vuln.affected || []).filter((a) => a.package?.name === pkg.name && a.package?.ecosystem === pkg.ecosystem).flatMap((a) => (a.ranges || []).map((r) => ({ type: r.type, events: (r.events || []).slice(0, 20) }))).slice(0, 4),
    aliases: (vuln.aliases || []).slice(0, 12),
    modified: vuln.modified || null,
    published: vuln.published || null,
    withdrawn: vuln.withdrawn || null,
    cvss: extractCvss(vuln),
    cvssBaseScore: (() => { const vector = extractCvss(vuln); return vector ? cvss31BaseScore(vector) : null; })(),
    affectedPackages: (vuln.affected || []).map((a) => ({ ecosystem: a.package?.ecosystem || '', name: a.package?.name || '' })).filter((a) => a.name && a.ecosystem).slice(0, 40),
  };
}

function extractCvss(vuln) {
  for (const item of vuln.severity || []) if (item?.score) return String(item.score).slice(0, 160);
  return null;
}

function cvss31BaseScore(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const v = Object.fromEntries(vector.split('/').slice(1).map((part) => part.split(':')));
  const av = { N: .85, A: .62, L: .55, P: .2 }[v.AV];
  const ac = { L: .77, H: .44 }[v.AC];
  const ui = { N: .85, R: .62 }[v.UI];
  const scope = v.S;
  const c = { H: .56, L: .22, N: 0 }[v.C]; const i = { H: .56, L: .22, N: 0 }[v.I]; const a = { H: .56, L: .22, N: 0 }[v.A];
  const pr = scope === 'C' ? { N: .85, L: .68, H: .5 }[v.PR] : { N: .85, L: .62, H: .27 }[v.PR];
  if ([av, ac, ui, c, i, a, pr, scope].some((x) => x === undefined)) return null;
  const impactSub = 1 - (1-c)*(1-i)*(1-a);
  const impact = scope === 'U' ? 6.42*impactSub : 7.52*(impactSub-.029)-3.25*Math.pow(impactSub-.02,15);
  if (impact <= 0) return 0;
  const exploit = 8.22*av*ac*pr*ui;
  const raw = scope === 'U' ? Math.min(impact+exploit,10) : Math.min(1.08*(impact+exploit),10);
  return Math.ceil(raw*10 - 1e-9)/10;
}

function scoreSeverity(vuln) {
  // database_specific severity strings (GitHub Advisory, etc.)
  const db = vuln.database_specific || {};
  const label = String(db.severity || '').toUpperCase();
  if (label === 'CRITICAL') return 'critical';
  if (label === 'HIGH') return 'high';
  if (label === 'MODERATE' || label === 'MEDIUM') return 'medium';
  if (label === 'LOW') return 'low';

  const sevList = vuln.severity || [];
  for (const s of sevList) {
    if (!s || typeof s.score !== 'string') continue;
    // Numeric score: "9.8" or "7.5"
    const numeric = Number.parseFloat(s.score);
    if (Number.isFinite(numeric) && !s.score.includes(':') && !s.score.includes('/')) {
      if (numeric >= 9) return 'critical';
      if (numeric >= 7) return 'high';
      if (numeric >= 4) return 'medium';
      return 'low';
    }
    // CVSS vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    if (s.score.includes('CVSS')) {
      const numericScore = cvss31BaseScore(s.score);
      if (numericScore !== null) return numericScore >= 9 ? 'critical' : numericScore >= 7 ? 'high' : numericScore >= 4 ? 'medium' : 'low';
      const fromVector = severityFromCvssVector(s.score);
      if (fromVector) return fromVector;
    }
  }

  return 'medium'; // unknown → treat as medium so it is not hidden
}

/**
 * Rough CVSS v3/v4 base-severity from the vector string without a full calculator.
 * Uses impact (C/I/A) and privileges required (PR) as the main signal.
 */
function severityFromCvssVector(vector) {
  const parts = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((p) => {
        const [k, v] = p.split(':');
        return [k, v];
      })
      .filter(([k, v]) => k && v),
  );
  const impact = [parts.C, parts.I, parts.A].filter(Boolean);
  const highImpact = impact.filter((v) => v === 'H').length;
  const lowOnly = impact.length && impact.every((v) => v === 'L' || v === 'N');
  const pr = parts.PR; // N / L / H
  const ui = parts.UI; // N / R

  if (highImpact >= 2 && pr === 'N') return 'critical';
  if (highImpact >= 1 && (pr === 'N' || pr === 'L')) return 'high';
  if (highImpact >= 1) return 'high';
  if (lowOnly && pr === 'N' && ui === 'N') return 'medium';
  if (lowOnly) return 'low';
  if (highImpact === 0 && impact.some((v) => v === 'L')) return 'medium';
  return 'medium';
}

function buildFix(pkg, vuln) {
  const affected = vuln.affected || [];
  const ranges = [];
  for (const a of affected) {
    if (a.package?.name !== pkg.name || a.package?.ecosystem !== pkg.ecosystem) continue;
    for (const r of a.ranges || []) {
      if (r.type !== 'ECOSYSTEM' && r.type !== 'SEMVER') continue;
      const fixed = (r.events || []).filter((e) => e.fixed).map((e) => e.fixed);
      ranges.push(...fixed);
    }
    if (Array.isArray(a.versions)) {
      // some entries list exact vulnerable versions only
    }
  }
  const unique = [...new Set(ranges)].slice(0, 5);
  if (unique.length) {
    return `Upgrade ${pkg.name} to ${unique.join(' or ')} (or newer). Then reinstall from the lockfile.`;
  }
  return `Check the advisory for ${vuln.id} and upgrade ${pkg.name} to a non-affected version. Run your package manager's audit command for the exact fixed release.`;
}
