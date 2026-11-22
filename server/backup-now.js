// npm run backup: writes one copy of the database now, into FLAWRADAR_BACKUP_DIR (default ./backups).
import path from 'node:path';
import { config } from './config.js';
import { runBackup } from './backup.js';
import * as db from './db.js';

const dir = config.backup.dir || path.join(config.root, 'backups');
console.log(`Backup written: ${runBackup({ dir })}`);
db.close();
