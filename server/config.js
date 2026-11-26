import path from 'node:path';
import net from 'node:net';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Load .env if present. Real environment variables win over the file.
try {
  process.loadEnvFile(path.join(root, '.env'));
} catch {
  /* no .env file, that is fine */
}

const env = process.env;
// Prefer FLAWRADAR_*; fall back to legacy WSEC_* so old deploys keep working.
const envGet = (key) => env[`FLAWRADAR_${key}`] ?? env[`WSEC_${key}`];
const list = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
const num = (v, fallback) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const port = num(env.PORT, 3000);

// Validate published scanner IPs and the local bind address at startup.
const publicIps = list(envGet('PUBLIC_IPS'));
const invalidPublicIps = publicIps.filter((ip) => net.isIP(ip) === 0);
if (invalidPublicIps.length) {
  throw new Error('FLAWRADAR_PUBLIC_IPS contains invalid IP address(es): ' + invalidPublicIps.join(', '));
}
const egressIp = envGet('EGRESS_IP') || '';
if (egressIp) {
  if (net.isIP(egressIp) === 0) {
    throw new Error('FLAWRADAR_EGRESS_IP must be a local interface IP address, not a hostname.');
  }
  const localAddresses = Object.values(os.networkInterfaces()).flat().filter(Boolean).map((entry) => entry.address);
  if (!localAddresses.includes(egressIp)) {
    throw new Error('FLAWRADAR_EGRESS_IP must match an IP assigned to a local network interface. A NAT/public egress IP usually does not belong here.');
  }
}

export const config = {
  version: '0.1.0',
  root,
  port,
  host: env.HOST || '127.0.0.1',
  baseUrl: (envGet('BASE_URL') || `http://localhost:${port}`).replace(/\/+$/, ''),
  dataDir: envGet('DATA_DIR') || path.join(root, 'data'),
  contact: envGet('CONTACT') || 'saremisback@gmail.com',
  quiet: envGet('QUIET') === '1',

  // Addresses the scanner connects from. Shown on the Whitelist page.
  publicIps,
  // Bind outgoing scan connections to this local address.
  egressIp,
  // Read the client address from X-Forwarded-For (only behind a proxy you control).
  trustProxy: envGet('TRUST_PROXY') === '1',
  // Development only: allow scanning private addresses and custom ports.
  allowPrivate: envGet('ALLOW_PRIVATE') === '1',

  scansPerHour: num(envGet('SCANS_PER_HOUR'), 12),
  scansPerHostPerHour: num(envGet('SCANS_PER_HOST_PER_HOUR'), 6),
  // Hosts that publish a flawradar-allow record get this higher per-host limit.
  scansPerHostAllowedPerHour: num(envGet('SCANS_PER_HOST_ALLOWED_PER_HOUR'), 30),
  verifyChecksPerHour: num(envGet('VERIFY_PER_HOUR'), 30),
  maxConcurrentScans: num(envGet('MAX_CONCURRENT'), 4),
  maxQueuedScans: 50,
  retentionDays: num(envGet('RETENTION_DAYS'), 30),
  sourcePerHour: num(envGet('SOURCE_PER_HOUR'), 20),

  maxZipBytes: 10 * 1024 * 1024,
  maxSourceFiles: 3000,
  maxSourceTotalBytes: 30 * 1024 * 1024,
  maxSourceJsonBytes: 12 * 1024 * 1024,

  // Watches: scheduled rescans of hosts whose owners proved control, with an email when the
  // grade drops. Switched on by setting FLAWRADAR_SMTP_HOST.
  mail: {
    enabled: Boolean(envGet('SMTP_HOST')),
    host: envGet('SMTP_HOST') || '',
    port: num(envGet('SMTP_PORT'), 587),
    // tls = connect with TLS (port 465), starttls = upgrade (port 587), none = plain (tests only)
    secure: envGet('SMTP_SECURE') || (num(envGet('SMTP_PORT'), 587) === 465 ? 'tls' : 'starttls'),
    user: envGet('SMTP_USER') || '',
    pass: envGet('SMTP_PASS') || '',
    from: envGet('SMTP_FROM') || '',
  },
  watchIntervalHours: num(envGet('WATCH_INTERVAL_HOURS'), 24),
  maxWatchesPerEmail: num(envGet('MAX_WATCHES_PER_EMAIL'), 5),
  watchSignupsPerHour: num(envGet('WATCH_SIGNUPS_PER_HOUR'), 6),

  // Automatic copies of the database. Empty directory = off.
  backup: {
    dir: envGet('BACKUP_DIR') || '',
    keep: num(envGet('BACKUP_KEEP'), 7),
    intervalHours: num(envGet('BACKUP_INTERVAL_HOURS'), 24),
  },

  requestTimeoutMs: 10_000,
  maxPageBytes: 750_000,
  scanTimeoutMs: 90_000,

  // Hosts whose owners asked not to be scanned (see the Acceptable Use Policy). A listed
  // name also covers its subdomains. Comma separated, applied after a restart.
  blockedHosts: list(envGet('BLOCKED_HOSTS')).map((h) => h.toLowerCase().replace(/^\.+|\.+$/g, '')),

  // The version of the Terms, Acceptable Use Policy and Privacy Policy that people accept
  // before a scan. Change it whenever you change those pages in a way that matters; everyone
  // then has to accept again. The scan record keeps the version that was accepted.
  termsVersion: '2026-11-22',

  // Filled into the legal pages. Anything left empty shows as a highlighted
  // placeholder on the page, so you can see what still needs completing.
  legal: {
    entity: envGet('LEGAL_ENTITY') || 'Sarem Menur',

    email: envGet('LEGAL_EMAIL') || 'saremisback@gmail.com',
    law: envGet('LEGAL_LAW') || 'the laws of the Federal Democratic Republic of Ethiopia',

    hosting: envGet('LEGAL_HOSTING') || 'the hosting and email service providers selected by the Operator; provider and processing region may change',
    logRetention: envGet('LEGAL_LOG_RETENTION') || 'Scan reports are retained for the period stated in the Privacy Policy.',
  },
};

export const isLocalUrl = (url) => /^https?:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\])/i.test(url);

/** The user agent site owners see in their logs. Never carries a local development address. */
export function userAgent() {
  return isLocalUrl(config.baseUrl)
    ? `FlawRadar-Scanner/${config.version}`
    : `FlawRadar-Scanner/${config.version} (+${config.baseUrl}/whitelist)`;
}
