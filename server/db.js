import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

const file = process.env.FLAWRADAR_DB || path.join(config.dataDir, 'flawradar.db');
if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });

const db = new DatabaseSync(file);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    url         TEXT NOT NULL,
    deep        INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL,
    progress    TEXT NOT NULL DEFAULT '[]',
    score       INTEGER,
    grade       TEXT,
    result      TEXT,
    error       TEXT,
    created_at  INTEGER NOT NULL,
    finished_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS scans_host_created ON scans (host, created_at);

  CREATE TABLE IF NOT EXISTS verifications (
    host       TEXT PRIMARY KEY,
    token      TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

// Databases created before terms were recorded get the column added.
if (!db.prepare('PRAGMA table_info(scans)').all().some((c) => c.name === 'terms_version')) {
  db.exec('ALTER TABLE scans ADD COLUMN terms_version TEXT');
}

if (!db.prepare('PRAGMA table_info(scans)').all().some((c) => c.name === 'delete_hash')) {
  db.exec('ALTER TABLE scans ADD COLUMN delete_hash TEXT');
}

db.exec(`
  CREATE TABLE IF NOT EXISTS watches (
    id            TEXT PRIMARY KEY,
    host          TEXT NOT NULL,
    email         TEXT NOT NULL,
    secret        TEXT NOT NULL,
    confirmed     INTEGER NOT NULL DEFAULT 0,
    paused        TEXT,
    created_at    INTEGER NOT NULL,
    confirmed_at  INTEGER,
    last_run_at   INTEGER,
    last_scan_id  TEXT,
    last_score    INTEGER,
    last_grade    TEXT,
    last_alert_at INTEGER,
    UNIQUE (host, email)
  );
  CREATE INDEX IF NOT EXISTS watches_due ON watches (confirmed, paused, last_run_at);
`);
if (!db.prepare('PRAGMA table_info(watches)').all().some((c) => c.name === 'url')) {
  db.exec('ALTER TABLE watches ADD COLUMN url TEXT');
}

// Public vulnerability intelligence is cached separately from user scans. No uploaded source,
// dependency inventory, local file path, or scan identifier is persisted in these tables.
db.exec(`
  CREATE TABLE IF NOT EXISTS cve_intel (
    osv_id TEXT PRIMARY KEY, cve_id TEXT, summary TEXT, details TEXT, severity TEXT,
    cvss_vector TEXT, cvss_base REAL, epss_score REAL, epss_percentile REAL,
    kev INTEGER NOT NULL DEFAULT 0, kev_date_added TEXT, kev_due_date TEXT, kev_action TEXT,
    published TEXT, modified TEXT, aliases_json TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]', affected_json TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS cve_intel_severity_updated ON cve_intel(severity, updated_at DESC);
  CREATE TABLE IF NOT EXISTS cve_aliases (
    osv_id TEXT NOT NULL REFERENCES cve_intel(osv_id) ON DELETE CASCADE,
    alias TEXT NOT NULL, PRIMARY KEY(osv_id, alias)
  );
  CREATE INDEX IF NOT EXISTS cve_alias_lookup ON cve_aliases(alias);
  CREATE TABLE IF NOT EXISTS cve_affected_packages (
    osv_id TEXT NOT NULL REFERENCES cve_intel(osv_id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL, package_name TEXT NOT NULL, PRIMARY KEY(osv_id, ecosystem, package_name)
  );
  CREATE INDEX IF NOT EXISTS cve_package_lookup ON cve_affected_packages(ecosystem, package_name);
  CREATE TABLE IF NOT EXISTS vulnerability_relationships (
    source_id TEXT NOT NULL, target_id TEXT NOT NULL, relation TEXT NOT NULL,
    PRIMARY KEY(source_id, target_id, relation)
  );
`);

const cveUpsert = db.prepare(`INSERT INTO cve_intel
  (osv_id,cve_id,summary,details,severity,cvss_vector,cvss_base,epss_score,epss_percentile,kev,kev_date_added,kev_due_date,kev_action,published,modified,aliases_json,references_json,affected_json,updated_at)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  ON CONFLICT(osv_id) DO UPDATE SET cve_id=excluded.cve_id,summary=excluded.summary,details=excluded.details,severity=excluded.severity,
  cvss_vector=excluded.cvss_vector,cvss_base=excluded.cvss_base,epss_score=excluded.epss_score,epss_percentile=excluded.epss_percentile,
  kev=excluded.kev,kev_date_added=excluded.kev_date_added,kev_due_date=excluded.kev_due_date,kev_action=excluded.kev_action,
  published=excluded.published,modified=excluded.modified,aliases_json=excluded.aliases_json,references_json=excluded.references_json,
  affected_json=excluded.affected_json,updated_at=excluded.updated_at`);
const cveAliasDelete = db.prepare('DELETE FROM cve_aliases WHERE osv_id = ?');
const cveAliasInsert = db.prepare('INSERT OR IGNORE INTO cve_aliases(osv_id,alias) VALUES(?,?)');
const cvePackageDelete = db.prepare('DELETE FROM cve_affected_packages WHERE osv_id = ?');
const cvePackageInsert = db.prepare('INSERT OR IGNORE INTO cve_affected_packages(osv_id,ecosystem,package_name) VALUES(?,?,?)');
const cveRelationDelete = db.prepare('DELETE FROM vulnerability_relationships WHERE source_id = ?');
const cveRelationInsert = db.prepare('INSERT OR IGNORE INTO vulnerability_relationships(source_id,target_id,relation) VALUES(?,?,?)');
const cveRecent = db.prepare('SELECT * FROM cve_intel ORDER BY updated_at DESC LIMIT ?');
const cveAliasesFor = db.prepare('SELECT alias FROM cve_aliases WHERE osv_id = ? ORDER BY alias');
const cvePackagesFor = db.prepare('SELECT ecosystem, package_name AS name FROM cve_affected_packages WHERE osv_id = ? ORDER BY ecosystem, package_name');

const q = {
  insert: db.prepare(
    'INSERT INTO scans (id, host, url, deep, status, progress, created_at, terms_version, delete_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ),
  status: db.prepare('UPDATE scans SET status = ? WHERE id = ?'),
  progress: db.prepare('UPDATE scans SET progress = ? WHERE id = ?'),
  finish: db.prepare(
    'UPDATE scans SET status = ?, score = ?, grade = ?, result = ?, finished_at = ? WHERE id = ?',
  ),
  fail: db.prepare("UPDATE scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?"),
  get: db.prepare('SELECT * FROM scans WHERE id = ?'),
  previous: db.prepare(
    "SELECT id, score, grade, result, created_at FROM scans WHERE host = ? AND id != ? AND status = 'done' AND created_at < ? ORDER BY created_at DESC LIMIT 1",
  ),
  countHost: db.prepare('SELECT COUNT(*) AS n FROM scans WHERE host = ? AND created_at >= ?'),
  purge: db.prepare('DELETE FROM scans WHERE created_at < ?'),
  remove: db.prepare('DELETE FROM scans WHERE id = ?'),
  removeHost: db.prepare('DELETE FROM scans WHERE host = ?'),
  // Unconfirmed watch sign-ups that nobody confirmed are forgotten after two days.
  purgeWatches: db.prepare('DELETE FROM watches WHERE confirmed = 0 AND created_at < ?'),
  watchInsert: db.prepare('INSERT INTO watches (id, host, email, secret, created_at, url) VALUES (?, ?, ?, ?, ?, ?)'),
  watchById: db.prepare('SELECT * FROM watches WHERE id = ?'),
  watchByHostEmail: db.prepare('SELECT * FROM watches WHERE host = ? AND email = ?'),
  watchCountEmail: db.prepare('SELECT COUNT(*) AS n FROM watches WHERE email = ?'),
  watchesByEmail: db.prepare('SELECT * FROM watches WHERE email = ? ORDER BY created_at'),
  watchConfirm: db.prepare('UPDATE watches SET confirmed = 1, confirmed_at = ?, paused = NULL WHERE id = ?'),
  watchDelete: db.prepare('DELETE FROM watches WHERE id = ?'),
  watchPause: db.prepare('UPDATE watches SET paused = ? WHERE id = ?'),
  watchDue: db.prepare('SELECT * FROM watches WHERE confirmed = 1 AND paused IS NULL AND (last_run_at IS NULL OR last_run_at < ?) ORDER BY last_run_at LIMIT ?'),
  watchRan: db.prepare('UPDATE watches SET last_run_at = ?, last_scan_id = ?, last_score = ?, last_grade = ? WHERE id = ?'),
  watchTouch: db.prepare('UPDATE watches SET last_run_at = ? WHERE id = ?'),
  watchAlerted: db.prepare('UPDATE watches SET last_alert_at = ? WHERE id = ?'),
  watchCount: db.prepare('SELECT COUNT(*) AS n FROM watches WHERE confirmed = 1 AND paused IS NULL'),
  scanCount: db.prepare('SELECT COUNT(*) AS n FROM scans'),
  getToken: db.prepare('SELECT token FROM verifications WHERE host = ?'),
  putToken: db.prepare('INSERT OR IGNORE INTO verifications (host, token, created_at) VALUES (?, ?, ?)'),
  // Anything still queued or running when the process died will never finish.
  orphans: db.prepare(
    "UPDATE scans SET status = 'failed', error = 'The server restarted during this scan. Run it again.', finished_at = ? WHERE status IN ('queued', 'running')",
  ),
};

export function insertScan({ id, host, url, deep, createdAt, termsVersion, deleteHash }) {
  q.insert.run(id, host, url, deep ? 1 : 0, 'queued', '[]', createdAt, termsVersion ?? null, deleteHash ?? null);
}
export const setStatus = (id, status) => q.status.run(status, id);
export const setProgress = (id, steps) => q.progress.run(JSON.stringify(steps), id);
export function finishScan(id, { status, score, grade, result }) {
  q.finish.run(status, score ?? null, grade ?? null, JSON.stringify(result), Date.now(), id);
}
export const failScan = (id, message) => q.fail.run(message, Date.now(), id);
export const getScan = (id) => q.get.get(id);
export const previousScan = (host, id, createdAt) => q.previous.get(host, id, createdAt);
export const countHostScansSince = (host, since) => q.countHost.get(host, since).n;
export const purgeOlderThan = (ts) => q.purge.run(ts).changes;
export const deleteScan = (id) => q.remove.run(id).changes > 0;
export const deleteHostScans = (host) => q.removeHost.run(host).changes;

export const insertWatch = ({ id, host, email, secret, url }) => q.watchInsert.run(id, host, email, secret, Date.now(), url ?? null);
export const getWatch = (id) => q.watchById.get(id);
export const getWatchFor = (host, email) => q.watchByHostEmail.get(host, email);
export const countWatchesFor = (email) => q.watchCountEmail.get(email).n;
export const watchesFor = (email) => q.watchesByEmail.all(email);
export const confirmWatch = (id) => q.watchConfirm.run(Date.now(), id);
export const deleteWatch = (id) => q.watchDelete.run(id).changes > 0;
export const pauseWatch = (id, reason) => q.watchPause.run(reason, id);
export const dueWatches = (olderThan, limit = 5) => q.watchDue.all(olderThan, limit);
export const watchRan = (id, { scanId, score, grade }) => q.watchRan.run(Date.now(), scanId, score ?? null, grade ?? null, id);
export const watchTouched = (id) => q.watchTouch.run(Date.now(), id);
export const watchAlerted = (id) => q.watchAlerted.run(Date.now(), id);
export const purgeStaleWatches = () => q.purgeWatches.run(Date.now() - 2 * 86_400_000).changes;

/** Cache only public advisory intelligence; never cache the uploaded project's package list. */
export function storeCveIntel(findings = []) {
  const unique = new Map();
  for (const f of findings) if (f?.osvId && !unique.has(f.osvId)) unique.set(f.osvId, f);
  if (!unique.size) return 0;
  db.exec('BEGIN');
  try {
    for (const f of unique.values()) {
      const aliases = [...new Set([...(f.aliases || []), f.cve].filter((v) => typeof v === 'string' && v.length <= 100))];
      const affected = Array.isArray(f.affectedPackages) ? f.affectedPackages : [];
      const kev = f.kev || null; const epss = f.epss || null;
      cveUpsert.run(f.osvId, f.cve || null, String(f.why || '').slice(0, 500), String(f.advisoryDetails || '').slice(0, 12000), f.severity || 'unknown', f.cvss || null, Number.isFinite(f.cvssBaseScore) ? f.cvssBaseScore : null, Number.isFinite(epss?.score) ? epss.score : null, Number.isFinite(epss?.percentile) ? epss.percentile : null, kev ? 1 : 0, kev?.dateAdded || null, kev?.dueDate || null, String(kev?.requiredAction || '').slice(0, 1000), f.published || null, f.modified || null, JSON.stringify(aliases), JSON.stringify(f.advisoryReferences || []), JSON.stringify(f.affectedRanges || []), Date.now());
      cveAliasDelete.run(f.osvId); cvePackageDelete.run(f.osvId); cveRelationDelete.run(f.osvId);
      for (const alias of aliases) { cveAliasInsert.run(f.osvId, alias); cveRelationInsert.run(f.osvId, alias, 'alias'); }
      for (const pkg of affected) if (pkg?.ecosystem && pkg?.name) cvePackageInsert.run(f.osvId, String(pkg.ecosystem).slice(0,80), String(pkg.name).slice(0,214));
    }
    db.exec('COMMIT');
  } catch (err) { db.exec('ROLLBACK'); throw err; }
  return unique.size;
}

export function recentCveIntel(limit = 100) {
  const rows = cveRecent.all(Math.max(1, Math.min(250, Number(limit) || 100)));
  return rows.map((row) => ({ ...row, aliases: cveAliasesFor.all(row.osv_id).map((x) => x.alias), affectedPackages: cvePackagesFor.all(row.osv_id), references: JSON.parse(row.references_json || '[]'), affectedRanges: JSON.parse(row.affected_json || '[]'), kev: Boolean(row.kev) }));
}

export function stats() {
  return { scans: q.scanCount.get().n, activeWatches: q.watchCount.get().n };
}

/** A consistent copy of the whole database, made while the app keeps running. */
export function backupTo(file) {
  db.exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`);
}
export const failOrphans = () => q.orphans.run(Date.now()).changes;
export const getToken = (host) => q.getToken.get(host)?.token;
export const putToken = (host, token) => q.putToken.run(host, token, Date.now());

export function close() {
  db.close();
}