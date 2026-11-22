import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';
import * as db from './db.js';

// Automatic copies of the database. VACUUM INTO writes a consistent copy while the app keeps
// running, so there is no need to stop anything. Old copies beyond FLAWRADAR_BACKUP_KEEP are removed.
// Reports are temporary by design, so this is mostly about watches and ownership tokens.

export const state = { lastAt: null, lastFile: null, lastError: null };

const NAME = /^flawradar-\d{8}-\d{6}\.db$/;

export function runBackup({ dir = config.backup.dir, keep = config.backup.keep, now = new Date() } = {}) {
  if (!dir) return null;
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stamp = now.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
  const file = path.join(dir, `flawradar-${stamp}.db`);
  try {
    if (fs.existsSync(file)) fs.unlinkSync(file);
    db.backupTo(file);
    fs.chmodSync(file, 0o600);
    const old = fs.readdirSync(dir).filter((f) => NAME.test(f)).sort().reverse().slice(keep);
    for (const f of old) fs.unlinkSync(path.join(dir, f));
    state.lastAt = Date.now();
    state.lastFile = file;
    state.lastError = null;
    return file;
  } catch (err) {
    state.lastError = err.message;
    throw err;
  }
}

export function startBackups() {
  if (!config.backup.dir) return null;
  const run = () => {
    try {
      const f = runBackup();
      if (f) console.log(`Database backup written: ${f}`);
    } catch (err) {
      console.error('Database backup failed:', err.message);
    }
  };
  run();
  const timer = setInterval(run, config.backup.intervalHours * 3_600_000);
  timer.unref();
  return timer;
}
