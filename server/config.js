import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Load .env if present. Real environment variables win over the file.
try {
  process.loadEnvFile(path.join(root, '.env'));
} catch {
  /* no .env file, that is fine */
}

const env = process.env;
const list = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
const num = (v, fallback) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const port = num(env.PORT, 3000);

export const config = {
  version: '0.1.0',
  root,
  port,
  host: env.HOST || '127.0.0.1',
  baseUrl: (env.WSEC_BASE_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
  dataDir: env.WSEC_DATA_DIR || path.join(root, 'data'),
  contact: env.WSEC_CONTACT || '',
  quiet: env.WSEC_QUIET === '1',

  // Addresses the scanner connects from. Shown on the Whitelist page.
  publicIps: list(env.WSEC_PUBLIC_IPS),
  // Bind outgoing scan connections to this local address.
  egressIp: env.WSEC_EGRESS_IP || '',
  // Read the client address from X-Forwarded-For (only behind a proxy you control).
  trustProxy: env.WSEC_TRUST_PROXY === '1',
  // Development only: allow scanning private addresses and custom ports.
  allowPrivate: env.WSEC_ALLOW_PRIVATE === '1',

  scansPerHour: num(env.WSEC_SCANS_PER_HOUR, 12),
  scansPerHostPerHour: num(env.WSEC_SCANS_PER_HOST_PER_HOUR, 6),
  verifyChecksPerHour: num(env.WSEC_VERIFY_PER_HOUR, 30),
  maxConcurrentScans: num(env.WSEC_MAX_CONCURRENT, 4),
  maxQueuedScans: 50,
  retentionDays: num(env.WSEC_RETENTION_DAYS, 30),

  // Source upload scanning. Code is analysed in memory and never stored.
  sourcePerHour: num(env.WSEC_SOURCE_PER_HOUR, 20),
  maxSourceFiles: 3000,
  maxFileBytes: 512 * 1024,
  maxSourceTotalBytes: 30 * 1024 * 1024,
  maxZipBytes: 10 * 1024 * 1024,
  maxSourceJsonBytes: 12 * 1024 * 1024,

  requestTimeoutMs: 10_000,
  maxPageBytes: 750_000,
  scanTimeoutMs: 90_000,
};

export function userAgent() {
  return `Wsec-Scanner/${config.version} (+${config.baseUrl}/whitelist)`;
}