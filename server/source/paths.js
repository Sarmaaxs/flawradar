// Which uploaded files are worth reading, and how to name them safely.

export const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'vendor', 'dist', 'build', '.next', '.nuxt', '.cache',
  '__pycache__', 'venv', '.venv', 'bower_components', 'coverage', '.idea', '.vscode', 'target',
]);

const SKIP_FILE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Pipfile\.lock|poetry\.lock|Gemfile\.lock|\.DS_Store)$|\.min\.(?:js|css)$|\.map$/i;

const TEXT_EXT = new Set([
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte',
  'py', 'php', 'phtml', 'inc',
  'html', 'htm', 'ejs', 'hbs', 'twig',
  'json', 'yml', 'yaml', 'toml', 'ini', 'conf', 'cfg', 'config', 'env', 'properties',
  'txt', 'sh', 'rb', 'java', 'go', 'cs', 'htaccess',
]);

/** Clean a path from an upload. Returns null for anything that tries to climb out of the root. */
export function normalizePath(input) {
  if (typeof input !== 'string') return null;
  const parts = input.replace(/\\/g, '/').replace(/\0/g, '').split('/').filter((p) => p && p !== '.');
  if (!parts.length || parts.some((p) => p === '..')) return null;
  return parts.join('/').slice(0, 500);
}

export function skippedDir(path) {
  return path.split('/').slice(0, -1).find((seg) => SKIP_DIRS.has(seg)) || null;
}

export function baseName(path) {
  return path.slice(path.lastIndexOf('/') + 1);
}

export function extension(path) {
  const name = baseName(path).toLowerCase();
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1) : dot === 0 ? name.slice(1) : '';
}

export function isTestPath(path) {
  return /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|mocks?|examples?|samples?|docs?)\//i.test(path) || /\.(?:test|spec)\.[a-z]+$/i.test(path);
}

/** Dependency manifests are skipped by the line rules but still read for the known-vulnerability lookup. */
export const MANIFEST_FOR_CVE = /(?:^|\/)(?:package-lock\.json|package\.json|requirements[\w.-]*\.txt)$/i;

/** Returns a reason string when the file should not be read, otherwise null. */
export function skipReason(path) {
  const dir = skippedDir(path);
  if (dir) return `folder:${dir}`;
  if (SKIP_FILE.test(path)) return 'generated';
  const name = baseName(path).toLowerCase();
  if (name.startsWith('.env') || name.startsWith('dockerfile') || name === '.htaccess') return null;
  if (!TEXT_EXT.has(extension(path))) return 'type';
  return null;
}