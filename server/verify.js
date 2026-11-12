import crypto from 'node:crypto';
import * as db from './db.js';
import { fetchUrl } from './scanner/fetcher.js';
import { makeResolver } from './scanner/dnsinfo.js';
import { portsFor } from './scanner/scan.js';

const FILE_PATH = '/.well-known/wsec-verify.txt';

/** One stable token per host. The owner can leave the proof in place. */
export function tokenFor(host) {
  let token = db.getToken(host);
  if (!token) {
    db.putToken(host, crypto.randomBytes(16).toString('hex'));
    token = db.getToken(host);
  }
  return token;
}

export function instructions(target) {
  const value = `wsec-verify=${tokenFor(target.host)}`;
  return {
    host: target.host,
    value,
    file: { path: FILE_PATH, content: value },
    dns: { name: `_wsec.${target.host}`, type: 'TXT', value },
  };
}

/**
 * Deep scans send more requests than a normal visit, so they need proof that the
 * person asking controls the host. The proof is checked again every time, so
 * removing the file or record withdraws permission straight away.
 *
 * Accepted proof, either of:
 *   - a file at /.well-known/wsec-verify.txt on that exact host containing the value
 *   - a TXT record at _wsec.<host> containing the value
 */
export async function checkOwnership(target, { resolver, ports = portsFor(target) } = {}) {
  const { value } = instructions(target);
  const tried = [];

  for (const scheme of ['https', 'http']) {
    const port = ports[scheme];
    const suffix = port === (scheme === 'https' ? 443 : 80) ? '' : `:${port}`;
    const url = `${scheme}://${target.hostUrl}${suffix}${FILE_PATH}`;
    try {
      const res = await fetchUrl(url, { maxBytes: 2000, timeoutMs: 8000, maxRedirects: 2 });
      const sameHost = new URL(res.url).hostname.replace(/^\[|\]$/g, '') === target.host;
      const lines = res.body.split(/\r?\n/).map((l) => l.trim());
      if (res.status === 200 && sameHost && lines.includes(value)) {
        return { verified: true, method: 'file', tried };
      }
      tried.push({
        method: 'file',
        where: url,
        result: res.status !== 200 ? `HTTP ${res.status}` : !sameHost ? 'redirected to another host' : 'value not found in file',
      });
    } catch (err) {
      tried.push({ method: 'file', where: url, result: err.code || err.message });
    }
  }

  if (!target.isIp) {
    const name = `_wsec.${target.host}`;
    try {
      const records = (await (resolver || makeResolver()).resolveTxt(name)).map((chunks) => chunks.join(''));
      if (records.includes(value)) return { verified: true, method: 'dns', tried };
      tried.push({ method: 'dns', where: name, result: records.length ? 'value not found in TXT records' : 'no TXT record' });
    } catch (err) {
      tried.push({ method: 'dns', where: name, result: err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'no TXT record' : err.code || err.message });
    }
  }

  return { verified: false, tried };
}
