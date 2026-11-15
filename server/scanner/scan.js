import { config } from '../config.js';
import { AppError } from '../errors.js';
import { fetchUrl, pickAddress } from './fetcher.js';
import { resolvePublic } from './net.js';
import { inspectTls } from './tls.js';
import { lookupDns } from './dnsinfo.js';
import { runDeepProbes } from './deep.js';
import { evaluate, PROBE_ORIGIN } from './checks.js';
import { summarize } from './score.js';

const DEFAULT_PORTS = { http: 80, https: 443 };

/** Ports to use for a target. Custom ports only exist in development mode. */
export function portsFor(target) {
  return target.port ? { http: target.port, https: target.port } : DEFAULT_PORTS;
}

function originFor(target, scheme, ports) {
  const defaultPort = scheme === 'https' ? 443 : 80;
  const port = ports[scheme];
  return `${scheme}://${target.hostUrl}${port === defaultPort ? '' : `:${port}`}`;
}

// A failed request is data for the checks. A refused target is a real error.
async function tryFetch(url, options) {
  try {
    return { res: await fetchUrl(url, options) };
  } catch (err) {
    if (err instanceof AppError) throw err;
    return { error: err.code || err.message || 'error' };
  }
}

function detectBlock(res) {
  const status = res.status;
  if (![403, 406, 429, 503].includes(status)) return null;
  const h = res.headers;
  const body = res.body.slice(0, 20_000).toLowerCase();
  let vendor = null;
  if (h['cf-ray'] || /cloudflare/i.test(h.server || '')) vendor = 'Cloudflare';
  else if (h['x-sucuri-id'] || /sucuri/i.test(h.server || '')) vendor = 'Sucuri';
  else if (h['x-iinfo'] || /incapsula/i.test(body)) vendor = 'Imperva';
  else if (/akamai/i.test(h.server || '') || /akamai/.test(body)) vendor = 'Akamai';
  else if (h['x-amzn-waf-action']) vendor = 'AWS WAF';
  if (status === 503 && !vendor) return null; // an ordinary outage
  return { status, vendor };
}

async function findSecurityTxt(base) {
  for (const path of ['/.well-known/security.txt', '/security.txt']) {
    const r = await tryFetch(`${base}${path}`, { maxBytes: 8192 });
    const res = r.res;
    if (res && res.status === 200 && /^\s*Contact:/im.test(res.body) && !/<html/i.test(res.body.slice(0, 200))) {
      const expires = /^\s*Expires:\s*(.+)$/im.exec(res.body)?.[1]?.trim() || null;
      return { found: true, path, expires };
    }
  }
  return { found: false };
}


const MAX_CRAWL_PAGES = 3;
const CRAWL_CANDIDATES = ['/login', '/signin', '/account', '/app', '/dashboard', '/admin', '/about', '/contact', '/pricing', '/docs'];

/** Same-origin internal paths from the home page, plus a few common routes. */
function pickCrawlPaths(homeRes, limit = MAX_CRAWL_PAGES) {
  const origin = new URL(homeRes.url).origin;
  const host = new URL(homeRes.url).hostname;
  const seen = new Set(['/', '']);
  const out = [];

  const consider = (raw) => {
    if (!raw || raw.startsWith('#') || raw.startsWith('mailto:') || raw.startsWith('javascript:')) return;
    let u;
    try {
      u = new URL(raw, homeRes.url);
    } catch {
      return;
    }
    if (u.origin !== origin) return;
    if (u.hostname !== host) return;
    const path = u.pathname || '/';
    if (seen.has(path)) return;
    if (/\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|pdf|zip|xml|json)(?:$|\?)/i.test(path)) return;
    seen.add(path);
    out.push(path);
  };

  for (const m of homeRes.body.matchAll(/\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)) {
    consider(m[1]);
    if (out.length >= limit * 3) break;
  }
  for (const p of CRAWL_CANDIDATES) consider(p);

  // Prefer short, interesting paths
  out.sort((a, b) => a.split('/').length - b.split('/').length || a.length - b.length);
  return out.slice(0, limit);
}

async function crawlExtraPages(homeRes, base, tryFetchFn) {
  const paths = pickCrawlPaths(homeRes);
  const pages = [];
  for (const path of paths) {
    const r = await tryFetchFn(`${base}${path}`, { maxBytes: 200_000, maxRedirects: 3 });
    if (!r.res || r.res.status >= 400) continue;
    const finalHost = new URL(r.res.url).hostname;
    const homeHost = new URL(homeRes.url).hostname;
    if (finalHost !== homeHost) continue;
    pages.push({ path, res: r.res });
    if (pages.length >= MAX_CRAWL_PAGES) break;
  }
  return pages;
}

/**
 * Run every check against a target.
 *
 * @param target  result of parseTarget()
 * @param options { deep, onStep(name, state), resolver, ports }
 */
export async function runScan(target, options = {}) {
  const { deep = false, onStep = () => {}, resolver, ports = portsFor(target) } = options;
  const started = Date.now();

  const ctx = {
    host: target.host,
    ports,
    page: null,
    extraPages: [],
    http: null,
    tls: null,
    cors: null,
    dns: null,
    securityTxt: null,
    deep: null,
  };

  const step = async (name, fn, { soft = false } = {}) => {
    onStep(name, 'running');
    try {
      const value = await fn();
      onStep(name, 'done');
      return value;
    } catch (err) {
      onStep(name, 'failed');
      if (!soft || err instanceof AppError) throw err;
      return undefined;
    }
  };

  // 1. Load the home page. HTTPS first, plain HTTP as a fallback.
  await step('Load the home page', async () => {
    const viaHttps = await tryFetch(`${originFor(target, 'https', ports)}/`);
    if (viaHttps.res) {
      ctx.page = { res: viaHttps.res, https: new URL(viaHttps.res.url).protocol === 'https:' };
      return;
    }
    const viaHttp = await tryFetch(`${originFor(target, 'http', ports)}/`);
    if (!viaHttp.res) {
      throw new AppError(
        502,
        'unreachable',
        `Could not connect to ${target.host} over HTTPS (${viaHttps.error}) or HTTP (${viaHttp.error}).`,
      );
    }
    ctx.page = { res: viaHttp.res, https: false, httpsError: viaHttps.error };
  });

  const base = new URL(ctx.page.res.url).origin;
  const summaryBase = {
    host: target.host,
    finalUrl: ctx.page.res.url,
    ip: ctx.page.res.address,
    https: ctx.page.https,
    deep: Boolean(deep),
    scannerVersion: config.version,
  };

  // If a firewall answered instead of the site, the results would describe the firewall.
  const blocked = detectBlock(ctx.page.res);
  if (blocked) {
    return {
      ...summaryBase,
      blocked,
      findings: [],
      counts: null,
      score: null,
      grade: null,
      durationMs: Date.now() - started,
    };
  }

  // 2. Independent probes, run together.
  const tasks = [];
  if (ctx.page.https) {
    tasks.push(
      step(
        'Inspect the TLS certificate',
        async () => {
          const address = pickAddress(await resolvePublic(target.host));
          ctx.tls = await inspectTls({ host: target.host, address: address.address, port: ports.https });
        },
        { soft: true },
      ),
    );
  }
  tasks.push(
    step(
      'Check the HTTP to HTTPS redirect',
      async () => {
        ctx.http = await tryFetch(`${originFor(target, 'http', ports)}/`, { follow: false, maxBytes: 20_000 });
      },
      { soft: true },
    ),
    step(
      'Probe CORS',
      async () => {
        ctx.cors = await tryFetch(ctx.page.res.url, {
          follow: false,
          maxBytes: 20_000,
          headers: { Origin: PROBE_ORIGIN },
        });
      },
      { soft: true },
    ),
    step(
      'Look for security.txt',
      async () => {
        ctx.securityTxt = await findSecurityTxt(base);
      },
      { soft: true },
    ),
  );
  if (!target.isIp) {
    tasks.push(
      step(
        'Read DNS records',
        async () => {
          ctx.dns = await lookupDns(target.host, resolver);
        },
        { soft: true },
      ),
    );
  }
  await Promise.all(tasks);

  // 2b. A few same-origin pages so path-only headers are not missed.
  await step(
    'Check a few more pages',
    async () => {
      ctx.extraPages = await crawlExtraPages(ctx.page.res, base, tryFetch);
    },
    { soft: true },
  );

  // 3. Deep probes, only when the caller has already proved ownership.
  if (deep) {
    await step(
      'Look for exposed files',
      async () => {
        ctx.deep = await runDeepProbes((path, opts) => tryFetch(`${base}${path}`, opts));
      },
      { soft: true },
    );
  }

  const findings = evaluate(ctx);
  const summary = summarize(findings);

  return {
    ...summaryBase,
    blocked: null,
    pagesChecked: 1 + (ctx.extraPages?.length || 0),
    findings,
    ...summary,
    tls: ctx.tls?.ok
      ? {
          protocol: ctx.tls.protocol,
          cipher: ctx.tls.cipher?.name || null,
          issuer: ctx.tls.cert?.issuer || null,
          validTo: ctx.tls.cert?.validTo || null,
        }
      : null,
    durationMs: Date.now() - started,
  };
}
