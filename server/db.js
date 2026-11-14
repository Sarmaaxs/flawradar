import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { config } from './config.js';

const file = process.env.WSEC_DB || path.join(config.dataDir, 'wsec.db');
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

const q = {
  insert: db.prepare(
    'INSERT INTO scans (id, host, url, deep, status, progress, created_at, terms_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
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
  getToken: db.prepare('SELECT token FROM verifications WHERE host = ?'),
  putToken: db.prepare('INSERT OR IGNORE INTO verifications (host, token, created_at) VALUES (?, ?, ?)'),
  // Anything still queued or running when the process died will never finish.
  orphans: db.prepare(
    "UPDATE scans SET status = 'failed', error = 'The server restarted during this scan. Run it again.', finished_at = ? WHERE status IN ('queued', 'running')",
  ),
};

export function insertScan({ id, host, url, deep, createdAt, termsVersion }) {
  q.insert.run(id, host, url, deep ? 1 : 0, 'queued', '[]', createdAt, termsVersion ?? null);
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
export const failOrphans = () => q.orphans.run(Date.now()).changes;
export const getToken = (host) => q.getToken.get(host)?.token;
export const putToken = (host, token) => q.putToken.run(host, token, Date.now());

export function close() {
  db.close();
}