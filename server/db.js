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
    "SELECT id, score, grade, created_at FROM scans WHERE host = ? AND id != ? AND status = 'done' AND created_at < ? ORDER BY created_at DESC LIMIT 1",
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