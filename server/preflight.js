import net from 'node:net';
import { config, isLocalUrl } from './config.js';

/**
 * Things that must be true before this is shown to the public. Returns a list of
 * { level: 'error' | 'warn', message }. Nothing here stops the server from starting,
 * because a local copy for development is fine with all of it.
 */
export function preflight(cfg = config, env = process.env) {
  const out = [];
  const add = (level, message) => out.push({ level, message });
  const isHttps = cfg.baseUrl.startsWith('https://');
  const local = isLocalUrl(cfg.baseUrl);

  if (cfg.allowPrivate) add('error', 'FLAWRADAR_ALLOW_PRIVATE=1 lets people scan private addresses. Never use it on a public instance.');
  if (local) {
    add('warn', 'FLAWRADAR_BASE_URL is a local address. Set it to the public https address of the site.');
  } else if (!isHttps) {
    add('warn', 'FLAWRADAR_BASE_URL is not https. Put the site behind https; HSTS is only sent for https.');
  }

  if (!cfg.publicIps.length) {
    add('error', 'FLAWRADAR_PUBLIC_IPS is empty. The Whitelist page has nothing true to publish.');
  } else {
    for (const ip of cfg.publicIps) {
      if (!net.isIP(ip)) add('error', `FLAWRADAR_PUBLIC_IPS contains "${ip}", which is not an IP address.`);
      else if (/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|fc|fd|fe80|::1)/i.test(ip)) add('error', `FLAWRADAR_PUBLIC_IPS contains ${ip}, a private address nobody can allow-list.`);
      else if (/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8)/i.test(ip)) add('error', `FLAWRADAR_PUBLIC_IPS contains ${ip}, a documentation address from .env.example. Put your real one.`);
    }
  }
  if (cfg.egressIp && !net.isIP(cfg.egressIp)) add('error', `FLAWRADAR_EGRESS_IP "${cfg.egressIp}" is not an IP address.`);
  if (!cfg.contact) add('warn', 'FLAWRADAR_CONTACT is empty. The Whitelist page should show an abuse contact.');
  if (!cfg.trustProxy && !local) add('warn', 'FLAWRADAR_TRUST_PROXY is 0. If a reverse proxy sits in front, every visitor shares one rate limit. Set it to 1 only when the proxy is the sole way in.');
  if (cfg.trustProxy && local) add('warn', 'FLAWRADAR_TRUST_PROXY=1 on a local address: anyone can fake X-Forwarded-For.');

  const missing = Object.entries(cfg.legal).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) add('error', `Legal details missing (FLAWRADAR_LEGAL_*): ${missing.join(', ')}. The legal pages show yellow placeholders until you fill them in, and a lawyer should read them.`);

  if (cfg.mail.enabled) {
    if (!cfg.mail.from) add('error', 'Watch emails are on but FLAWRADAR_SMTP_FROM is empty.');
  } else {
    add('warn', 'FLAWRADAR_SMTP_HOST is not set, so watches (scheduled rescans with email alerts) are switched off.');
  }
  if (!cfg.backup.dir) add('warn', 'FLAWRADAR_BACKUP_DIR is not set, so there are no automatic database backups.');
  return out;
}

export function printPreflight(items = preflight(), log = console.log) {
  if (!items.length) return log('Preflight: all checks passed.');
  log('Preflight:');
  for (const { level, message } of items) log(`  ${level === 'error' ? 'FIX ' : 'note'}  ${message}`);
}
