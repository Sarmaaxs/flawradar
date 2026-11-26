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

async function findSecurityTxt(base, disallow = []) {
  let skipped = false;
  for (const path of ['/.well-known/security.txt', '/security.txt']) {
    if (robotsDisallowsPath(path, disallow)) { skipped = true; continue; }
    const r = await tryFetch(`${base}${path}`, { maxBytes: 8192 });
    const res = r.res;
    if (res && res.status === 200 && /^\s*Contact:/im.test(res.body) && !/<html/i.test(res.body.slice(0, 200))) {
      const expires = /^\s*Expires:\s*(.+)$/im.exec(res.body)?.[1]?.trim() || null;
      return { found: true, path, expires };
    }
  }
  return { found: false, skippedByRobots: skipped };
}


const MAX_CRAWL_PAGES = 5;
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
  out.sort((a, b) => {
    const priority = (p) => /(?:admin|dashboard|login|log-in|signin|sign-in|account|portal|manage|console)/i.test(p) ? 0 : 1;
    return priority(a) - priority(b) || a.split('/').length - b.split('/').length || a.length - b.length;
  });
  return out.slice(0, limit);
}

export function robotsDisallowRules(text) {
  const rules = [];
  let wildcard = false;
  let groupHasRules = false;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const match = /^([^:]+):\s*(.*)$/i.exec(line);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    const value = match[2].trim();
    if (key === 'user-agent') {
      if (groupHasRules) { wildcard = false; groupHasRules = false; }
      wildcard = wildcard || value === '*';
    } else if (key === 'disallow' && wildcard && value.startsWith('/')) {
      rules.push(value); groupHasRules = true;
    } else if (key === 'allow' && wildcard) groupHasRules = true;
  }
  return [...new Set(rules)];
}

export function robotsDisallowsPath(pathname, rules = []) {
  return rules.some((rule) => rule && pathname.startsWith(rule));
}

export function sitemapPaths(xml, base, rules = []) {
  const origin = new URL(base).origin;
  const host = new URL(base).hostname;
  const paths = [];
  for (const match of String(xml || '').matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
    try {
      const url = new URL(match[1].replace(/&amp;/g, '&').trim(), base);
      if (url.origin !== origin || url.hostname !== host || !['http:', 'https:'].includes(url.protocol)) continue;
      if (robotsDisallowsPath(url.pathname, rules)) continue;
      if (/\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|pdf|zip|xml|json)$/i.test(url.pathname)) continue;
      paths.push(url.pathname);
    } catch {}
  }
  return [...new Set(paths)].slice(0, 40);
}

async function crawlExtraPages(homeRes, base, tryFetchFn, { onPage = () => {}, onRobots = () => {} } = {}) {
  // Respect the site's published crawler exclusions. robots.txt is not access control;
  // this scanner simply avoids fetching paths the owner asked crawlers to leave alone.
  const robots = await tryFetchFn(`${base}/robots.txt`, { maxBytes: 60_000, timeoutMs: 3000 });
  const rules = robots.res?.status === 200 ? robotsDisallowRules(robots.res.body) : [];
  const sitemaps = [];
  if (robots.res?.status === 200) {
    for (const line of robots.res.body.split(/\r?\n/)) {
      const match = /^\s*Sitemap:\s*(\S+)/i.exec(line);
      if (!match) continue;
      try { const u = new URL(match[1], base); if (u.origin === base) sitemaps.push(u.href); } catch {}
    }
  }
  const sitemapHints = [...new Set(sitemaps)].slice(0, 5);
  const sitemapFetchTargets = sitemapHints.length ? sitemapHints : [`${base}/sitemap.xml`];
  let sitemapPage = null;
  for (const url of sitemapFetchTargets.slice(0, 1)) {
    let sitemapPath = '/sitemap.xml';
    try { sitemapPath = new URL(url).pathname; } catch {}
    if (robotsDisallowsPath(sitemapPath, rules)) continue;
    const result = await tryFetchFn(url, { maxBytes: 100_000, timeoutMs: 3000 });
    if (result.res?.status === 200 && /<(?:urlset|sitemapindex)\b/i.test(result.res.body.slice(0, 2000))) {
      sitemapPage = result.res;
      break;
    }
  }
  const fromSitemap = sitemapPage ? sitemapPaths(sitemapPage.body, base, rules) : [];
  onRobots({ disallow: rules, sitemaps: sitemapHints.length ? sitemapHints : (sitemapPage ? [sitemapPage.url] : []), paths: fromSitemap, found: Boolean(robots.res?.status === 200), sitemapFound: Boolean(sitemapPage) });

  const candidates = [...new Set([...pickCrawlPaths(homeRes, MAX_CRAWL_PAGES * 3), ...fromSitemap])]
    .filter((pathname) => !robotsDisallowsPath(pathname, rules));
  candidates.sort((a, b) => {
    const priority = (p) => /(?:admin|dashboard|login|log-in|signin|sign-in|account|portal|manage|console)/i.test(p) ? 0 : 1;
    return priority(a) - priority(b) || a.split('/').length - b.split('/').length || a.length - b.length;
  });
  const pages = [];
  for (const pathname of candidates.slice(0, MAX_CRAWL_PAGES * 2)) {
    const r = await tryFetchFn(`${base}${pathname}`, { maxBytes: 180_000, maxRedirects: 2, timeoutMs: 3500 });
    if (!r.res || (r.res.status >= 400 && ![401, 403].includes(r.res.status))) continue;
    const finalHost = new URL(r.res.url).hostname;
    const homeHost = new URL(homeRes.url).hostname;
    if (finalHost !== homeHost) continue;
    const finalUrl = new URL(r.res.url);
    finalUrl.search = ''; finalUrl.hash = '';
    const safeRes = { ...r.res, url: finalUrl.href };
    const page = { path: pathname, res: safeRes };
    pages.push(page);
    onPage({ url: finalUrl.href, body: r.res.body, headers: r.res.headers, status: r.res.status, path: pathname, source: fromSitemap.includes(pathname) ? 'sitemap' : 'same-origin link or route' });
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
  const { deep = false, onStep = () => {}, onPage = () => {}, onRobots = () => {}, resolver, ports = portsFor(target) } = options;
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
      const safeHome = new URL(viaHttps.res.url); safeHome.search = ''; safeHome.hash = '';
      onPage({ url: safeHome.href, body: viaHttps.res.body, headers: viaHttps.res.headers, status: viaHttps.res.status, path: '/', source: 'homepage' });
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
    const safeHome = new URL(viaHttp.res.url); safeHome.search = ''; safeHome.hash = '';
    onPage({ url: safeHome.href, body: viaHttp.res.body, headers: viaHttp.res.headers, status: viaHttp.res.status, path: '/', source: 'homepage' });
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
      ctx.extraPages = await crawlExtraPages(ctx.page.res, base, tryFetch, { onPage, onRobots: (info) => { ctx.robotsInfo = info; onRobots(info); } });
    },
    { soft: true },
  );
  await step('Look for security.txt', async () => {
    ctx.securityTxt = await findSecurityTxt(base, ctx.robotsInfo?.disallow || []);
  }, { soft: true });

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
    securityTxt: ctx.securityTxt || { found: false },
    durationMs: Date.now() - started,
  };
}
