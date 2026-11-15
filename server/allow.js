/**
 * Optional "I allow FlawRadar" signal from a site owner.
 *
 * When present, the host gets a higher per-host rate limit so legitimate
 * re-scans are less likely to look like noise. The signal is checked on each
 * scan request; removing it restores normal limits immediately.
 *
 * Accepted forms (either is enough):
 *   - DNS TXT at _flawradar.<host> containing a line/value starting with flawradar-allow=1
 *   - File at /.well-known/flawradar-allow.txt containing flawradar-allow=1
 *
 * Optional: flawradar-allow=1; contact=security@example.com
 */

import { fetchUrl } from './scanner/fetcher.js';
import { makeResolver } from './scanner/dnsinfo.js';
import { portsFor } from './scanner/scan.js';

const FILE_PATH = '/.well-known/flawradar-allow.txt';
const DNS_NAME = (host) => `_flawradar.${host}`;

/** @returns {{ allowed: boolean, method?: string, contact?: string|null, tried: object[] }} */
export async function checkAllow(target, { resolver, ports = portsFor(target) } = {}) {
  const tried = [];

  // DNS first — cheaper and works even when the site is down or behind auth.
  if (!target.isIp) {
    const name = DNS_NAME(target.host);
    try {
      const records = (await (resolver || makeResolver()).resolveTxt(name)).map((chunks) => chunks.join(''));
      for (const record of records) {
        const parsed = parseAllowValue(record);
        if (parsed) {
          return { allowed: true, method: 'dns', contact: parsed.contact, tried };
        }
      }
      tried.push({
        method: 'dns',
        where: name,
        result: records.length ? 'no flawradar-allow=1 in TXT records' : 'no TXT record',
      });
    } catch (err) {
      tried.push({
        method: 'dns',
        where: name,
        result: err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'no TXT record' : err.code || err.message,
      });
    }
  }

  for (const scheme of ['https', 'http']) {
    const port = ports[scheme];
    const suffix = port === (scheme === 'https' ? 443 : 80) ? '' : `:${port}`;
    const url = `${scheme}://${target.hostUrl}${suffix}${FILE_PATH}`;
    try {
      const res = await fetchUrl(url, { maxBytes: 2000, timeoutMs: 8000, maxRedirects: 2 });
      const sameHost = new URL(res.url).hostname.replace(/^\[|\]$/g, '') === target.host;
      if (res.status === 200 && sameHost) {
        for (const line of res.body.split(/\r?\n/)) {
          const parsed = parseAllowValue(line.trim());
          if (parsed) {
            return { allowed: true, method: 'file', contact: parsed.contact, tried };
          }
        }
        tried.push({ method: 'file', where: url, result: 'flawradar-allow=1 not found in file' });
      } else {
        tried.push({
          method: 'file',
          where: url,
          result: res.status !== 200 ? `HTTP ${res.status}` : 'redirected to another host',
        });
      }
    } catch (err) {
      tried.push({ method: 'file', where: url, result: err.code || err.message });
    }
  }

  return { allowed: false, tried };
}

/** Public instructions for the whitelist / docs pages. */
export function allowInstructions(host) {
  return {
    host,
    dns: {
      name: DNS_NAME(host),
      type: 'TXT',
      value: 'flawradar-allow=1',
      example: 'flawradar-allow=1; contact=security@example.com',
    },
    file: {
      path: FILE_PATH,
      content: 'flawradar-allow=1',
    },
  };
}

/**
 * Accept "flawradar-allow=1" or "flawradar-allow=1; contact=..." (case-insensitive key).
 * @returns {{ contact: string|null } | null}
 */
export function parseAllowValue(text) {
  if (!text || typeof text !== 'string') return null;
  const trimmed = text.trim();
  // Whole record or one line
  const m = /(?:^|[;\s])flawradar-allow\s*=\s*1(?:\s|;|$)/i.exec(` ${trimmed}`);
  if (!m) return null;
  const contact = /(?:^|[;\s])contact\s*=\s*([^\s;]+)/i.exec(trimmed);
  return { contact: contact ? contact[1].trim() : null };
}
