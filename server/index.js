import { config } from './config.js';
import * as db from './db.js';
import { createServer } from './app.js';
import { printPreflight } from './preflight.js';
import { startWatcher } from './watch.js';
import { startBackups } from './backup.js';

const orphans = db.failOrphans();
if (orphans) console.log(`Marked ${orphans} unfinished scans from the last run as failed.`);

const purge = () => {
  db.purgeStaleWatches();
  const removed = db.purgeOlderThan(Date.now() - config.retentionDays * 86_400_000);
  if (removed) console.log(`Deleted ${removed} reports older than ${config.retentionDays} days.`);
};
purge();
setInterval(purge, 3_600_000).unref();

const server = createServer();
server.listen(config.port, config.host, () => {
  console.log(`FlawRadar ${config.version} listening on http://${config.host}:${config.port}`);
  if (!config.quiet) printPreflight();
  startWatcher();
  startBackups();
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
