import { RULES, ruleCatalog } from './rules.js';
import { runFileChecks } from './filechecks.js';
import { runCveChecks } from './cves.js';
import { MANIFEST_FOR_CVE, extension, isTestPath, normalizePath, skipReason } from './paths.js';

export { ruleCatalog };

// This file runs in two places: on the server (the API) and in the visitor's browser (the source page).
// Keep it free of Node-only imports.
const DEFAULT_MAX_FILE_BYTES = 512 * 1024;

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const MAX_LINE = 1000; // longer lines are minified or generated; skip them
const PER_RULE_PER_FILE = 5;
const MAX_FINDINGS = 400;

// Applied to every snippet so a finding never shows a secret in full.
const KNOWN_SECRETS = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
];

function mask(value) {
  return `${value.slice(0, 3)}***`;
}

export function redactSecrets(text) {
  let out = text;
  for (const re of KNOWN_SECRETS) out = out.replace(re, mask);
  return out;
}

function isComment(trimmed) {
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('<!--');
}

const rulesByExt = new Map();
function rulesFor(ext) {
  if (!rulesByExt.has(ext)) rulesByExt.set(ext, RULES.filter((r) => !r.exts || r.exts.includes(ext)));
  return rulesByExt.get(ext);
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * Analyse uploaded files in memory. Nothing is written anywhere.
 *
 * @param input    [{ path, content }]
 * @param options  { skipped: [{ path, reason }] } files a caller already dropped (for example from a zip)
 */
export async function analyzeFiles(input, options = {}) {
  const started = Date.now();
  const maxFileBytes = options.maxFileBytes || DEFAULT_MAX_FILE_BYTES;
  const skipped = [...(options.skipped || [])];
  const seen = new Set();
  const files = [];
  const manifestFiles = []; // lockfiles / requirements kept for CVE checks
  const allPaths = [];

  for (const item of input) {
    const path = normalizePath(item.path);
    if (!path) {
      skipped.push({ path: String(item.path).slice(0, 80), reason: 'path' });
      continue;
    }
    if (seen.has(path)) continue;
    seen.add(path);
    allPaths.push(path);
    const reason = skipReason(path);
    if (reason) {
      skipped.push({ path, reason });
      // Still keep dependency manifests for OSV lookup (they are skipped for line rules).
      if (MANIFEST_FOR_CVE.test(path) && item.content && !item.content.includes('\0') && item.content.length <= maxFileBytes) {
        manifestFiles.push({ path, content: item.content });
      }
    } else if (item.content.length > maxFileBytes) {
      skipped.push({ path, reason: 'large' });
    } else if (item.content.includes('\0')) {
      skipped.push({ path, reason: 'binary' });
    } else {
      files.push({ path, content: item.content });
      if (MANIFEST_FOR_CVE.test(path)) manifestFiles.push({ path, content: item.content });
    }
  }
  // Paths a caller dropped before reading still count for the lockfile check.
  for (const s of options.skipped || []) {
    const p = normalizePath(s.path);
    if (p && !seen.has(p)) allPaths.push(p);
    // A caller that already read a lockfile hands over its text for the vulnerability lookup.
    if (p && typeof s.content === 'string' && MANIFEST_FOR_CVE.test(p)) manifestFiles.push({ path: p, content: s.content });
  }

  const findings = [];
  let lines = 0;
  let longLines = 0;
  let truncated = false;

  for (let i = 0; i < files.length; i += 1) {
    if (i % 40 === 39) await tick();
    const { path, content } = files[i];
    const ext = extension(path);
    const rules = rulesFor(ext);
    const test = isTestPath(path);
    const perRule = new Map();
    const rows = content.split('\n');
    lines += rows.length;

    for (let n = 0; n < rows.length; n += 1) {
      const line = rows[n];
      if (line.length > MAX_LINE) {
        longLines += 1;
        continue;
      }
      if (line.length < 4) continue;
      const trimmed = line.trim();
      const comment = isComment(trimmed);

      for (const rule of rules) {
        if (comment && !rule.secret) continue;
        if (test && rule.skipTests) continue;
        const m = rule.pattern.exec(line);
        if (!m) continue;
        if (rule.filter && !rule.filter(line, m)) continue;
        const count = perRule.get(rule.id) || 0;
        if (count >= PER_RULE_PER_FILE) continue;
        perRule.set(rule.id, count + 1);

        let snippet = trimmed;
        if (rule.redactCapture && m[1]) snippet = snippet.split(m[1]).join(mask(m[1]));
        snippet = redactSecrets(snippet);
        if (snippet.length > 200) snippet = `${snippet.slice(0, 200)}...`;
        findings.push({
          ruleId: rule.id, title: rule.title, severity: rule.severity, confidence: rule.confidence,
          file: path, line: n + 1, snippet, why: rule.why, fix: rule.fix,
        });
      }
    }
  }

  findings.push(...runFileChecks(files, allPaths));

  // Known CVEs from lockfiles / requirements (OSV). Failures become notices, not errors.
  let cveChecked = 0;
  let cvePackages = 0;
  const cveNotices = [];
  try {
    const cve = await runCveChecks(manifestFiles, options);
    findings.push(...cve.findings);
    cveChecked = cve.checked;
    cvePackages = cve.packages;
    cveNotices.push(...cve.notices);
  } catch {
    cveNotices.push('Vulnerability lookup failed unexpectedly and was skipped.');
  }

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
  if (findings.length > MAX_FINDINGS) {
    findings.length = MAX_FINDINGS;
    truncated = true;
  }

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) summary[f.severity] += 1;

  const skippedDirs = [...new Set(skipped.filter((s) => s.reason.startsWith('folder:')).map((s) => s.reason.slice(7)))];
  const notices = [];
  if (skippedDirs.length) notices.push(`Skipped folders: ${skippedDirs.join(', ')}. Dependencies and build output are not scanned.`);
  if (skipped.some((s) => s.reason === 'large')) notices.push(`Some files were larger than ${Math.round(maxFileBytes / 1024)} KB and were not read.`);
  if (longLines) notices.push(`${longLines} very long lines (minified or generated code) were skipped.`);
  if (truncated) notices.push(`Only the first ${MAX_FINDINGS} findings are shown.`);
  if (cvePackages) {
    notices.push(
      cveChecked
        ? `Checked ${cveChecked} package version${cveChecked === 1 ? '' : 's'} against the OSV vulnerability database.`
        : 'Vulnerability database was unreachable; known-CVE checks were skipped.',
    );
  }
  notices.push(...cveNotices);
  if (options.notices) notices.push(...options.notices);

  return {
    stats: {
      filesScanned: files.length,
      filesSkipped: skipped.length,
      lines,
      rules: RULES.length,
      packagesChecked: cveChecked,
      durationMs: Date.now() - started,
    },
    summary,
    findings,
    notices,
    truncated,
  };
}