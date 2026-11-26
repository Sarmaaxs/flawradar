import { Resolver } from 'node:dns/promises';

export function makeResolver() {
  return new Resolver({ timeout: 4000, tries: 2 });
}

const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'pro', 'biz', 'info', 'web']);

/**
 * Best guess at the registrable domain without a public suffix list.
 * Handles the common two-part endings like co.uk and com.au.
 */
export function registrableDomain(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const tld = parts[parts.length - 1];
  const sld = parts[parts.length - 2];
  if (tld.length === 2 && SECOND_LEVEL.has(sld)) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

// A lookup either answers (possibly with nothing) or fails. Failure returns null.
async function attempt(fn) {
  try {
    return await fn();
  } catch (err) {
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') return [];
    return null;
  }
}

const flatten = (records) => (records ? records.map((chunks) => chunks.join('')) : null);

/**
 * Collect the DNS records the checks need.
 * Each field is an array when the lookup worked and null when it failed.
 */
export async function lookupDns(host, resolver = makeResolver()) {
  const apex = registrableDomain(host);

  const [mx, apexTxt, hostTxt, dmarcHost, caaHost] = await Promise.all([
    attempt(() => resolver.resolveMx(apex)),
    attempt(() => resolver.resolveTxt(apex)),
    host === apex ? Promise.resolve([]) : attempt(() => resolver.resolveTxt(host)),
    attempt(() => resolver.resolveTxt(`_dmarc.${host}`)),
    attempt(() => resolver.resolveCaa(host)),
  ]);

  let dmarc = flatten(dmarcHost);
  if (dmarc && dmarc.length === 0 && host !== apex) {
    dmarc = flatten(await attempt(() => resolver.resolveTxt(`_dmarc.${apex}`)));
  }
  let caa = caaHost;
  if (caa && caa.length === 0 && host !== apex) {
    caa = await attempt(() => resolver.resolveCaa(apex));
  }

  const txt = [...(flatten(apexTxt) || []), ...(flatten(hostTxt) || [])];
  const spf = apexTxt === null && hostTxt === null ? null : txt.filter((t) => /^v=spf1(\s|$)/i.test(t));

  return {
    apex,
    mx: mx ? mx.map((m) => m.exchange) : null,
    spf,
    dmarc: dmarc ? dmarc.filter((t) => /^v=DMARC1/i.test(t)) : null,
    caa: caa ? caa.map((c) => `${c.issue || c.issuewild || c.iodef || ''}`) : null,
  };
}
