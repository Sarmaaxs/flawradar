import { config } from './config.js';
import * as db from './db.js';
import { createServer } from './app.js';

const orphans = db.failOrphans();
if (orphans) console.log(`Marked ${orphans} unfinished scans from the last run as failed.`);

const purge = () => {
  const removed = db.purgeOlderThan(Date.now() - config.retentionDays * 86_400_000);
  if (removed) console.log(`Deleted ${removed} reports older than ${config.retentionDays} days.`);
};
purge();
setInterval(purge, 3_600_000).unref();

const server = createServer();
server.listen(config.port, config.host, () => {
  console.log(`FlawRadar ${config.version} listening on http://${config.host}:${config.port}`);
  if (!config.publicIps.length) {
    console.log('No FLAWRADAR_PUBLIC_IPS set. The Whitelist page will say this instance has no published scanner addresses.');
  }
  if (config.allowPrivate) {
    console.log('FLAWRADAR_ALLOW_PRIVATE=1: private addresses and custom ports can be scanned. Do not use this in production.');
  }
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
