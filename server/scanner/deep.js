// Deep checks look for files and settings that should not be public.
// They only run against hosts whose owner has proved control (see verify.js).
//
// FlawRadar never stores or shows the content of these responses. A path counts
// as exposed only when the body matches a signature for that kind of file,
// so a site that answers 200 to everything does not produce false alarms.

const looksLikeEnv = (body) => {
  if (/<html|<!doctype/i.test(body.slice(0, 300))) return false;
  return body.split('\n').filter((line) => /^[A-Z][A-Z0-9_]*\s*=/.test(line)).length >= 2;
};
const sqlDump = (body) => /(CREATE TABLE|INSERT INTO|DROP TABLE)/i.test(body.slice(0, 4000));
const wpConfig = (body) => /DB_(NAME|USER|PASSWORD)/.test(body);
const zipFile = (body) => body.startsWith('PK\u0003\u0004');

export const EXPOSURES = [
  { group: 'vcs', path: '/.git/HEAD', test: (b) => /^ref:\s+refs\/heads\//.test(b) },
  { group: 'vcs', path: '/.git/config', test: (b) => /\[core\]/.test(b) },
  { group: 'env', path: '/.env', test: looksLikeEnv },
  { group: 'env', path: '/.env.production', test: looksLikeEnv },
  { group: 'env', path: '/.env.local', test: looksLikeEnv },
  { group: 'backup', path: '/wp-config.php.bak', test: wpConfig },
  { group: 'backup', path: '/wp-config.php~', test: wpConfig },
  { group: 'backup', path: '/wp-config.php.old', test: wpConfig },
  { group: 'backup', path: '/backup.sql', test: sqlDump },
  { group: 'backup', path: '/dump.sql', test: sqlDump },
  { group: 'backup', path: '/database.sql', test: sqlDump },
  { group: 'backup', path: '/backup.zip', test: zipFile },
  { group: 'backup', path: '/site.zip', test: zipFile },
  { group: 'misc', path: '/.DS_Store', test: (b) => b.includes('Bud1') },
  { group: 'misc', path: '/phpinfo.php', test: (b) => /phpinfo\(\)|PHP Version \d/.test(b) },
  { group: 'misc', path: '/server-status', test: (b) => /Apache Server Status/i.test(b) },
];

export const LISTING_PATHS = ['/', '/uploads/', '/files/', '/backup/', '/images/'];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * @param fetch async (path, options) => { res } | { error }
 */
export async function runDeepProbes(fetch, { delayMs = 120 } = {}) {
  const hits = [];
  const listings = [];
  let allow = null;

  for (const probe of EXPOSURES) {
    const r = await fetch(probe.path, { follow: false, maxBytes: 8192 });
    if (r.res && r.res.status === 200 && probe.test(r.res.body)) {
      hits.push({ group: probe.group, path: probe.path, status: r.res.status });
    }
    await sleep(delayMs);
  }

  for (const path of LISTING_PATHS) {
    const r = await fetch(path, { follow: false, maxBytes: 32_768 });
    if (r.res && r.res.status === 200 && /<title>\s*Index of \/|<h1>\s*Index of \//i.test(r.res.body)) {
      listings.push(path);
    }
    await sleep(delayMs);
  }

  const options = await fetch('/', { method: 'OPTIONS', follow: false, maxBytes: 2000 });
  const header = options.res?.headers?.allow;
  if (header) {
    allow = String(header)
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);
  }

  return { hits, listings, allow };
}
