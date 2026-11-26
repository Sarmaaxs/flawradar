import dns from 'node:dns/promises';
import { fetchUrl } from './fetcher.js';
import { resolvePublic } from './net.js';
import { registrableDomain, lookupDns, makeResolver } from './dnsinfo.js';
import { probeTls } from './tls.js';
import { extractResources } from './html.js';
import { lookupCves, intelligenceSignals } from '../source/cves.js';
import { calculateRiskPriority } from './risk.js';

const CT_URL = 'https://crt.sh/';
const CC_INFO_URL = 'https://index.commoncrawl.org/collinfo.json';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const MAX_CT_NAMES = 60;
const MAX_SCRIPT_FILES = 2;
const MAX_NODES = 180;
const MAX_EDGES = 360;
const MAX_BODY = 180000;
const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const nvdCache = new Map();
let nvdLastRequest = 0;
let nvdQueue = Promise.resolve();

const safeLabel = (value, max = 180) => String(value ?? '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max);
const unique = (values) => [...new Set(values.filter(Boolean))];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function makeGraph(root) {
  const nodes = [];
  const edges = [];
  const byId = new Map();
  const edgeSet = new Set();
  const addNode = (node) => {
    if (!node?.id) return null;
    if (byId.has(node.id)) {
      const existing = byId.get(node.id);
      if (ORDER[node.severity] !== undefined && ORDER[node.severity] < ORDER[existing.severity]) existing.severity = node.severity;
      if (String(node.detail || '').length > existing.detail.length) existing.detail = safeLabel(node.detail, 900);
      if (node.confidence === 'high') existing.confidence = 'high';
      if (node.source && !existing.source.split(' · ').includes(node.source)) existing.source = safeLabel(existing.source + ' · ' + node.source, 180);
      if (node.meta && typeof node.meta === 'object') {
        const merged = { ...existing.meta, ...node.meta };
        for (const key of ['references', 'affectedRanges', 'aliases', 'affectedPackages']) {
          if (Array.isArray(existing.meta[key]) || Array.isArray(node.meta[key])) {
            const values = [...(existing.meta[key] || []), ...(node.meta[key] || [])];
            merged[key] = [...new Map(values.map((value) => [JSON.stringify(value), value])).values()].slice(0, 30);
          }
        }
        existing.meta = merged;
      }
      return existing.id;
    }
    if (nodes.length >= MAX_NODES) return null;
    const clean = {
      id: safeLabel(node.id, 240),
      type: safeLabel(node.type || 'asset', 40),
      label: safeLabel(node.label || node.id, 140),
      detail: safeLabel(node.detail || '', 900),
      source: safeLabel(node.source || 'FlawRadar', 120),
      confidence: ['high', 'medium', 'low'].includes(node.confidence) ? node.confidence : 'medium',
      severity: ORDER[node.severity] !== undefined ? node.severity : 'info',
      href: typeof node.href === 'string' && /^https:\/\//i.test(node.href) ? node.href : null,
      meta: node.meta && typeof node.meta === 'object' ? node.meta : {},
    };
    nodes.push(clean);
    byId.set(clean.id, clean);
    return clean.id;
  };
  const addEdge = (source, target, relation) => {
    if (!source || !target || source === target || !byId.has(source) || !byId.has(target)) return;
    const key = source + '|' + target + '|' + relation;
    if (edgeSet.has(key) || edges.length >= MAX_EDGES) return;
    edgeSet.add(key);
    edges.push({ source, target, relation: safeLabel(relation || 'observed', 60) });
  };
  const rootId = addNode({ id: 'domain:' + root, type: 'domain', label: root, detail: 'Investigation root domain', source: 'Input', confidence: 'high' });
  return { nodes, edges, addNode, addEdge, rootId, byId };
}

async function optional(fn) {
  try { return await fn(); } catch { return null; }
}

async function fetchText(url, options = {}) {
  return fetchUrl(url, { maxBytes: MAX_BODY, timeoutMs: 3000, maxRedirects: 2, ...options });
}

export function parseRobots(text, origin) {
  const disallow = [];
  const sitemaps = [];
  let active = false;
  let groupHasRules = false;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const match = /^([^:]+):\s*(.*)$/i.exec(line);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    const value = match[2].trim();
    if (key === 'user-agent') {
      if (groupHasRules) { active = false; groupHasRules = false; }
      active = active || value === '*';
    } else if (key === 'disallow' && active && value.startsWith('/')) {
      disallow.push(value);
      groupHasRules = true;
    } else if (key === 'allow' && active) {
      groupHasRules = true;
    } else if (key === 'sitemap' && value) {
      try {
        const url = new URL(value, origin);
        if (url.origin === origin && !url.search) sitemaps.push(url.href);
      } catch {}
    }
  }
  return { disallow: unique(disallow).slice(0, 80), sitemaps: unique(sitemaps).slice(0, 5) };
}

export function isDisallowed(pathname, rules = []) {
  return rules.some((rule) => rule && pathname.startsWith(rule));
}

export function extractLinks(html, base) {
  const links = [];
  const content = String(html || '').replace(/<!--[\s\S]*?-->/g, '');
  for (const match of content.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi)) {
    const raw = match[1] ?? match[2] ?? match[3] ?? '';
    try {
      const url = new URL(raw, base);
      if (url.origin !== new URL(base).origin || !['http:', 'https:'].includes(url.protocol)) continue;
      url.search = '';
      url.hash = '';
      if (!/\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|pdf|zip|xml|json|mp4|mp3)$/i.test(url.pathname)) links.push(url.href);
    } catch {}
  }
  return unique(links).slice(0, 80);
}

export function sitemapLocations(xml, base) {
  const urls = [];
  for (const match of String(xml || '').matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
    try {
      const url = new URL(match[1].replace(/&amp;/g, '&').trim(), base);
      if (url.origin !== new URL(base).origin || !['http:', 'https:'].includes(url.protocol) || url.search) continue;
      url.hash = '';
      urls.push(url.href);
    } catch {}
  }
  return unique(urls).slice(0, 40);
}

export function fingerprint(html, headers = {}, resources = { scripts: [], styles: [], generator: null }) {
  const content = String(html || '').slice(0, 160000);
  const technologies = new Map();
  const add = (name, version, evidence) => {
    const key = name.toLowerCase();
    const previous = technologies.get(key);
    if (!previous || (!previous.version && version)) technologies.set(key, { name, version: version || null, evidence: safeLabel(evidence || 'HTML signature', 220) });
  };
  const server = headers.server || '';
  const powered = headers['x-powered-by'] || '';
  const generator = resources.generator || '';
  if (server) add(server.split(/[\s/]/)[0], server.match(/[\w.-]+\/([\d.]+)/)?.[1] || null, 'Server header: ' + server);
  if (powered) add(powered.split(/[\s/]/)[0], powered.match(/[\w.-]+\/([\d.]+)/)?.[1] || null, 'X-Powered-By: ' + powered);
  if (generator) add(generator.split(/[\s/]/)[0], generator.match(/[\d.]+/)?.[0] || null, 'Generator meta: ' + generator);

  const signatures = [
    ['WordPress', /wp-content\//i, /WordPress\s*([\d.]+)/i],
    ['Drupal', /drupalSettings|drupal\.js/i, /Drupal\s*([\d.]+)/i],
    ['Joomla', /content=.?Joomla!/i, /Joomla!?\s*([\d.]+)/i],
    ['Magento', /Magento_|mage\/cookies/i, /Magento\s*([\d.]+)/i],
    ['Next.js', /__NEXT_DATA__|_next\/static/i, null],
    ['Nuxt', /__NUXT__|_nuxt\//i, null],
    ['React', /data-reactroot|react\.production\.min\.js/i, null],
    ['Vue.js', /data-v-[a-f0-9]+|vue\.runtime/i, /Vue(?:\.js)?\s*([\d.]+)/i],
    ['Angular', /ng-version=|angular\.min\.js/i, /Angular\s*([\d.]+)/i],
    ['Svelte', /svelte-[a-z0-9]+/i, null],
    ['Shopify', /cdn\.shopify\.com|Shopify\.theme/i, null],
    ['Cloudflare', /__cf_bm|cf-ray/i, null],
    ['ASP.NET', /__VIEWSTATE|aspnet/i, null],
    ['Laravel', /laravel_session|csrf-token/i, null],
    ['Django', /csrfmiddlewaretoken|django/i, null],
    ['Ruby on Rails', /csrf-param|rails-ujs/i, null],
  ];
  for (const [name, pattern, versionPattern] of signatures) {
    if (!pattern.test(content)) continue;
    add(name, versionPattern ? content.match(versionPattern)?.[1] || null : null, 'Recognised HTML or asset signature');
  }
  for (const resource of [...(resources.scripts || []), ...(resources.styles || [])]) {
    const url = resource.url || '';
    const patterns = [
      ['jQuery', /jquery(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['Bootstrap', /bootstrap(?:\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['AngularJS', /angular(?:\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['Vue.js', /vue(?:\.runtime)?(?:\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['React', /react(?:-dom)?(?:\.production\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['Lodash', /lodash(?:\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['Moment.js', /moment(?:\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
      ['Axios', /axios(?:\.min)?(?:[-/@/])v?(\d+\.\d+(?:\.\d+)?)/i],
    ];
    for (const [name, pattern] of patterns) {
      const version = pattern.exec(url)?.[1];
      if (version) add(name, version, 'Versioned asset URL: ' + url);
    }
  }
  return [...technologies.values()].slice(0, 40);
}

export function extractApiEndpoints(content, base) {
  const paths = [];
  const patterns = [
    /(?:fetch|axios\.(?:get|post|put|patch|delete)|open)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /['"`](\/(?:api|graphql|rest|v[0-9]+\/api)(?:\/[^'"`\s]*)?)['"`]/gi,
  ];
  for (const pattern of patterns) {
    for (const match of String(content || '').matchAll(pattern)) {
      const raw = match[1];
      if (!raw || raw.startsWith('//') || raw.startsWith('data:')) continue;
      try {
        const url = new URL(raw, base);
        if (url.origin !== new URL(base).origin) continue;
        const params = [...new Set([...url.searchParams.keys()])].slice(0, 12);
        url.search = '';
        url.hash = '';
        if (url.pathname.length < 200 && !/\.(?:js|css|png|svg|woff2?)$/i.test(url.pathname)) paths.push({ url: url.href, params });
      } catch {}
    }
  }
  const byUrl = new Map(paths.map((item) => [item.url, item]));
  return [...byUrl.values()].slice(0, 60);
}

export function extractFormInputs(html, base) {
  const forms = [];
  for (const match of String(html || '').matchAll(/<form\b[\s\S]*?<\/form>/gi)) {
    const block = match[0];
    const open = /^<form\b[^>]*>/i.exec(block)?.[0] || '';
    const action = /\baction\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(open);
    const method = /\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(open);
    const raw = action?.[1] ?? action?.[2] ?? base;
    try {
      const url = new URL(raw || base, base);
      if (url.origin !== new URL(base).origin) continue;
      url.search = '';
      url.hash = '';
      const fields = [...block.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)]
        .map((item) => item[1] ?? item[2]).filter(Boolean).slice(0, 20);
      forms.push({ action: url.href, method: (method?.[1] ?? method?.[2] ?? 'GET').toUpperCase(), fields, password: /type\s*=\s*["']?password/i.test(block) });
    } catch {}
  }
  return forms.slice(0, 12);
}

async function collectCertificateNames(root) {
  try {
    const url = new URL(CT_URL);
    url.searchParams.set('q', '%25.' + root);
    url.searchParams.set('output', 'json');
    const response = await fetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'FlawRadar-Domain-Intelligence/1.0' }, signal: AbortSignal.timeout(6500) });
    if (!response.ok) return { names: [], notice: 'Certificate Transparency lookup returned HTTP ' + response.status + '.' };
    const body = await response.text();
    if (body.length > 1500000) return { names: [], notice: 'Certificate Transparency response exceeded the processing limit.' };
    const rows = JSON.parse(body);
    const names = unique(rows.flatMap((row) => String(row.name_value || '').split(/[\r\n]+/))
      .map((name) => name.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''))
      .filter((name) => /^[a-z0-9.-]+$/.test(name) && (name === root || name.endsWith('.' + root))));
    return { names: names.slice(0, MAX_CT_NAMES), notice: names.length > MAX_CT_NAMES ? 'Certificate Transparency returned more than ' + MAX_CT_NAMES + ' names; only the first ' + MAX_CT_NAMES + ' are shown.' : null };
  } catch {
    return { names: [], notice: 'Certificate Transparency data was unavailable. DNS and website mapping continued.' };
  }
}

async function commonCrawlUrls(root) {
  try {
    const infoResponse = await fetch(CC_INFO_URL, { headers: { Accept: 'application/json', 'User-Agent': 'FlawRadar-Domain-Intelligence/1.0' }, signal: AbortSignal.timeout(5000) });
    if (!infoResponse.ok) return { urls: [], notice: 'Common Crawl archive index was unavailable.' };
    const indexes = await infoResponse.json();
    const latest = Array.isArray(indexes) ? indexes[0]?.id : null;
    if (!latest || !/^[A-Z0-9-]+$/.test(latest)) return { urls: [], notice: 'Common Crawl did not return a usable index.' };
    const query = new URL('https://index.commoncrawl.org/' + latest + '-index');
    query.searchParams.set('url', '*.' + root + '/*');
    query.searchParams.set('output', 'json');
    query.searchParams.set('filter', 'status:200');
    query.searchParams.set('collapse', 'urlkey');
    query.searchParams.set('limit', '80');
    const response = await fetch(query, { headers: { Accept: 'application/x-ndjson', 'User-Agent': 'FlawRadar-Domain-Intelligence/1.0' }, signal: AbortSignal.timeout(6000) });
    if (!response.ok) return { urls: [], notice: 'Common Crawl archive query was unavailable.' };
    const raw = (await response.text()).slice(0, 180000);
    const urls = [];
    for (const line of raw.split(/\r?\n/).slice(0, 100)) {
      try {
        const row = JSON.parse(line);
        const url = new URL(row.url);
        if ((url.hostname === root || url.hostname.endsWith('.' + root)) && ['http:', 'https:'].includes(url.protocol)) {
          url.username = ''; url.password = '';
          url.search = '';
          url.hash = '';
          urls.push(url.href);
        }
      } catch {}
    }
    return { urls: unique(urls).slice(0, 60), notice: null, index: latest };
  } catch { return { urls: [], notice: 'Common Crawl archive data could not be reached.' }; }
}

async function discoverSubdomain(name) {
  const records = await optional(() => resolvePublic(name));
  return (records || []).map((record) => record.address).filter(Boolean);
}

function isInterestingPage(url) {
  return /(?:admin|dashboard|login|log-in|signin|sign-in|account|portal|manage|console)/i.test(new URL(url).pathname);
}

function severityOf(finding) {
  const value = String(finding.severity || '').toLowerCase();
  if (ORDER[value] !== undefined) return value;
  if (value === 'fail') return 'high';
  if (value === 'warn') return 'medium';
  return 'info';
}

const NVD_PRODUCTS = {
  apache: ['a', 'apache', 'http_server'],
  nginx: ['a', 'nginx', 'nginx'],
  wordpress: ['a', 'wordpress', 'wordpress'],
  drupal: ['a', 'drupal', 'drupal'],
  joomla: ['a', 'joomla', 'joomla'],
  magento: ['a', 'magento', 'magento'],
  php: ['a', 'php', 'php'],
  tomcat: ['a', 'apache', 'tomcat'],
  jquery: ['a', 'jquery', 'jquery'],
  bootstrap: ['a', 'getbootstrap', 'bootstrap'],
  openssl: ['a', 'openssl', 'openssl'],
  openresty: ['a', 'openresty', 'openresty'],
};

export function cpeFor(tech) {
  const key = String(tech.name || '').toLowerCase().replace(/\s+.*/, '');
  const product = NVD_PRODUCTS[key];
  if (!product || !tech.version || !/^[0-9][0-9a-zA-Z._+-]{0,39}$/.test(tech.version)) return null;
  return 'cpe:2.3:' + product[0] + ':' + product[1] + ':' + product[2] + ':' + tech.version + ':*:*:*:*:*:*:*';
}

function nvdSeverity(record) {
  const metrics = record.metrics || {};
  const metric = metrics.cvssMetricV40?.[0] || metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
  const data = metric?.cvssData || {};
  const score = Number(data.baseScore);
  const severity = String(data.baseSeverity || metric?.baseSeverity || '').toLowerCase();
  const valid = ORDER[severity] !== undefined;
  return {
    score: Number.isFinite(score) ? score : null,
    severity: valid ? severity : (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'info'),
    vector: data.vectorString || null,
  };
}

async function lookupNvdInner(tech) {
  const cpe = cpeFor(tech);
  if (!cpe) return { findings: [], notice: null };
  const cached = nvdCache.get(cpe);
  if (cached && Date.now() - cached.at < 12 * 60 * 60 * 1000) return { findings: cached.findings, notice: null };
  const wait = Math.max(0, 6500 - (Date.now() - nvdLastRequest));
  if (wait) await sleep(wait);
  try {
    const url = new URL(NVD_URL);
    url.searchParams.set('cpeName', cpe);
    url.searchParams.set('resultsPerPage', '15');
    nvdLastRequest = Date.now();
    const response = await fetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'FlawRadar-Domain-Intelligence/1.0' }, signal: AbortSignal.timeout(8000) });
    if (!response.ok) return { findings: [], notice: 'NVD product-version lookup returned HTTP ' + response.status + '.' };
    const body = await response.json();
    const findings = (body.vulnerabilities || []).map((row) => row.cve)
      .filter((cve) => cve && String(cve.vulnStatus || '').toLowerCase() !== 'rejected')
      .map((cve) => {
        const description = cve.descriptions?.find((item) => item.lang === 'en')?.value || 'No English description supplied.';
        const severity = nvdSeverity(cve);
        const refs = (cve.references || []).filter((item) => /^https:\/\//i.test(item.url || '')).slice(0, 4).map((item) => ({ type: 'WEB', url: item.url }));
        return {
          cve: cve.id,
          osvId: 'NVD-' + cve.id,
          published: cve.published || null,
          modified: cve.lastModified || null,
          package: tech.name,
          version: tech.version,
          ecosystem: 'CPE',
          severity: severity.severity,
          cvss: severity.vector,
          cvssBaseScore: severity.score,
          why: description.slice(0, 1800),
          advisoryDetails: description.slice(0, 8000),
          advisoryReferences: refs,
          affectedRanges: [],
          aliases: [cve.id],
          affectedPackages: [{ ecosystem: 'CPE', name: cpe }],
          fix: 'Compare this exact product version with the vendor advisory and upgrade to a release outside the affected CPE range.',
        };
      });
    nvdCache.set(cpe, { at: Date.now(), findings });
    return { findings, notice: null };
  } catch {
    return { findings: [], notice: 'NVD could not be reached; no NVD match is assumed.' };
  }
}

function lookupNvd(tech) {
  const task = nvdQueue.then(() => lookupNvdInner(tech));
  nvdQueue = task.then(() => undefined, () => undefined);
  return task;
}

function packageForTechnology(tech) {
  const names = {
    jquery: 'jquery', bootstrap: 'bootstrap', angularjs: 'angular',
    'vue.js': 'vue', react: 'react', lodash: 'lodash',
    'moment.js': 'moment', axios: 'axios',
  };
  const name = names[tech.name.toLowerCase()];
  if (!name || !tech.version || !/^\d+\.\d+(?:\.\d+)?$/.test(tech.version)) return null;
  const version = tech.version.split('.').length === 2 ? tech.version + '.0' : tech.version;
  return { name, version, ecosystem: 'npm', file: 'Public website asset fingerprint', line: 1 };
}

export async function runDomainIntelligence(target, { baseScan = null, pages = [], robotsInfo = null, networkPath = null } = {}) {
  const root = registrableDomain(target.host);
  const graph = makeGraph(target.host);
  const notices = [];
  const add = graph.addNode;
  const link = graph.addEdge;
  const rootId = graph.rootId;
  const resolver = makeResolver();

  if (networkPath?.hops?.length) {
    const pathId = add({
      id: 'network-path:' + target.host, type: 'network-path', label: 'Network route',
      detail: `${networkPath.method || 'Traceroute'} to ${networkPath.destination}; ${networkPath.metrics?.hopsObserved || networkPath.hops.length} hops observed; destination ${networkPath.metrics?.destinationReached ? 'reached' : 'not confirmed'}.`,
      source: 'Active network diagnostic', confidence: 'medium',
      meta: { metrics: networkPath.metrics, method: networkPath.method, destination: networkPath.destination },
    });
    link(rootId, pathId, 'network path');
    let previous = pathId;
    for (const hop of networkPath.hops) {
      const address = hop.addresses[0] || `no-response-${hop.ttl}`;
      const hopId = add({
        id: `network-hop:${hop.ttl}:${address}`, type: 'network-hop',
        label: `Hop ${hop.ttl}${hop.addresses[0] ? ' · ' + hop.addresses[0] : ' · no response'}`,
        detail: `${hop.probesAnswered}/${hop.probesSent} probes answered; RTT samples: ${hop.rttsMs.length ? hop.rttsMs.map((n) => n + ' ms').join(', ') : 'none'}. A timeout does not prove a host or router is absent.`,
        source: 'UDP traceroute', confidence: 'medium',
        meta: { ttl: hop.ttl, addresses: hop.addresses, rttsMs: hop.rttsMs, lossPercent: hop.lossPercent, reached: hop.reached },
      });
      link(previous, hopId, 'next route hop');
      previous = hopId;
    }
  }
  if (networkPath?.notice) notices.push(networkPath.notice);

  const [addresses, dnsInfo, mx, ns, txt, caa, ds, rootCname, cert, ct, archive] = await Promise.all([
    optional(() => resolvePublic(target.host)),
    optional(() => lookupDns(target.host, resolver)),
    optional(() => resolver.resolveMx(root)),
    optional(() => resolver.resolveNs(root)),
    optional(() => resolver.resolveTxt(root)),
    optional(() => resolver.resolveCaa(root)),
    optional(() => resolver.resolveDs(root)),
    optional(() => dns.resolveCname(target.host)),
    optional(async () => {
      const ips = await resolvePublic(target.host);
      return probeTls({ host: target.host, address: ips[0].address, port: 443, timeoutMs: 6000 });
    }),
    collectCertificateNames(root),
    commonCrawlUrls(root),
  ]);

  if (dnsInfo) {
    for (const ip of addresses || []) {
      const id = add({ id: 'ip:' + ip.address, type: 'ip', label: ip.address, detail: 'Resolved address for ' + target.host, source: 'DNS A/AAAA', confidence: 'high' });
      link(rootId, id, 'resolves to');
    }
    for (const host of unique((mx || []).map((item) => item.exchange))) {
      const id = add({ id: 'mx:' + host, type: 'mail', label: host, detail: 'Mail exchanger', source: 'DNS MX', confidence: 'high' });
      link(rootId, id, 'mail handled by');
    }
    for (const host of unique(ns || [])) {
      const id = add({ id: 'ns:' + host, type: 'nameserver', label: host, detail: 'Authoritative nameserver', source: 'DNS NS', confidence: 'high' });
      link(rootId, id, 'delegated to');
    }
    for (const item of (dnsInfo.spf || []).slice(0, 4)) {
      const id = add({ id: 'spf:' + root + ':' + item.slice(0, 30), type: 'dns', label: 'SPF policy', detail: item, source: 'DNS TXT', confidence: 'high' });
      link(rootId, id, 'publishes');
    }
    for (const item of (dnsInfo.dmarc || []).slice(0, 4)) {
      const id = add({ id: 'dmarc:' + root + ':' + item.slice(0, 30), type: 'dns', label: 'DMARC policy', detail: item, source: 'DNS TXT', confidence: 'high' });
      link(rootId, id, 'publishes');
    }
    for (const item of (txt || []).flat().map((x) => String(x)).filter((x) => /^(google-site-verification=|atlassian-domain-verification=)/i.test(x)).slice(0, 8)) {
      const id = add({ id: 'dns-txt:' + root + ':' + item.slice(0, 40), type: 'dns', label: item.slice(0, 48), detail: item, source: 'DNS TXT', confidence: 'high' });
      link(rootId, id, 'publishes');
    }
    if (ds?.length) {
      const id = add({ id: 'dnssec:' + root, type: 'dnssec', label: 'DNSSEC DS record', detail: 'A Delegation Signer record is published for this domain.', source: 'DNS DS lookup', confidence: 'high' });
      link(rootId, id, 'has DNSSEC delegation');
    } else if (ds) {
      const id = add({ id: 'dnssec:' + root + ':missing', type: 'dnssec', label: 'No DS record observed', detail: 'No DS record was returned. Confirm DNSSEC status with the registrar and authoritative DNS provider.', source: 'DNS DS lookup', confidence: 'medium' });
      link(rootId, id, 'DNSSEC status');
    }
    for (const item of unique((caa || []).map((x) => x.issue || x.issuewild || '').filter(Boolean))) {
      const id = add({ id: 'caa:' + item, type: 'dns', label: 'CAA ' + item, detail: 'Certificate Authority Authorization record', source: 'DNS CAA', confidence: 'high' });
      link(rootId, id, 'authorises');
    }
    for (const alias of rootCname || []) {
      const id = add({ id: 'cname:' + target.host + ':' + alias, type: 'dns-alias', label: alias, detail: 'CNAME target for ' + target.host, source: 'DNS CNAME', confidence: 'high' });
      link(rootId, id, 'aliases to');
    }
  } else notices.push('Some DNS records could not be resolved.');

  if (cert?.ok && cert.cert) {
    const certId = add({ id: 'certificate:' + target.host, type: 'certificate', label: 'TLS certificate', detail: 'Issuer: ' + cert.cert.issuer + '; valid: ' + cert.cert.validFrom + ' to ' + cert.cert.validTo + '; protocol: ' + cert.protocol, source: 'TLS handshake', confidence: 'high' });
    link(rootId, certId, 'presents');
    const sans = String(cert.cert.altNames || '').split(/,\s*/).map((x) => x.replace(/^DNS:/i, '').toLowerCase()).filter((x) => x === root || x.endsWith('.' + root));
    for (const name of sans.slice(0, 30)) {
      const id = add({ id: 'subdomain:' + name, type: 'subdomain', label: name, detail: 'Subject Alternative Name on the TLS certificate', source: 'TLS certificate', confidence: 'high' });
      link(certId, id, 'certificate covers');
    }
  } else notices.push('TLS certificate details were unavailable.');

  const ctNames = ct.names.filter((name) => name !== target.host && name !== root);
  for (const name of ctNames) {
    const id = add({ id: 'subdomain:' + name, type: 'subdomain', label: name, detail: 'Name appeared in a public Certificate Transparency log. This does not prove the host is active.', source: 'Certificate Transparency', confidence: 'medium' });
    link(rootId, id, 'certificate name');
  }
  if (ct.notice) notices.push(ct.notice);
  if (archive.notice) notices.push(archive.notice);
  for (const url of archive.urls) {
    const parsed = new URL(url);
    let parentId = rootId;
    if (parsed.hostname !== root && parsed.hostname !== target.host) {
      const subId = add({ id: 'subdomain:' + parsed.hostname, type: 'subdomain', label: parsed.hostname, detail: 'Hostname present in historical public crawl data.', source: 'Common Crawl', confidence: 'medium' });
      link(rootId, subId, 'historically indexed host');
      parentId = subId;
    }
    const id = add({ id: 'archive:' + url, type: 'historical-endpoint', label: parsed.pathname, detail: 'URL recorded in Common Crawl index ' + (archive.index || 'unknown') + '. This is historical metadata and was not requested from the target.', source: 'Common Crawl', confidence: 'medium', meta: { host: parsed.hostname, scheme: parsed.protocol } });
    link(parentId, id, 'historically indexed');
  }

  // Discovered subdomains are DNS-resolved only; no HTTP requests are sent to them.
  const takeoverSuffixes = ['github.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com', 'netlify.app', 'vercel.app', 'myshopify.com', 'surge.sh', 'pantheonsite.io', 'zendesk.com'];
  for (let start = 0; start < Math.min(ctNames.length, 20); start += 5) {
    const batch = ctNames.slice(start, start + 5);
    await Promise.all(batch.map(async (name) => {
      const aliases = await optional(() => dns.resolveCname(name));
      for (const alias of aliases || []) {
        const aliasId = add({ id: 'cname:' + name + ':' + alias, type: 'dns-alias', label: alias, detail: 'CNAME target for ' + name, source: 'DNS CNAME', confidence: 'high' });
        link('subdomain:' + name, aliasId, 'aliases to');
        if (takeoverSuffixes.some((suffix) => alias.toLowerCase().endsWith('.' + suffix))) {
          try { await dns.lookup(alias, { all: true }); }
          catch (err) {
            if (['ENOTFOUND', 'ENODATA'].includes(err.code)) {
              const warning = add({ id: 'finding:dangling-cname:' + name, type: 'finding', label: 'Possible dangling DNS alias', detail: 'The CNAME points to ' + alias + ', a hosted-service domain that did not resolve during this check. This is only a candidate; confirm with the provider before changing DNS.', severity: 'medium', source: 'DNS relationship analysis', confidence: 'low' });
              link(aliasId, warning, 'may be unclaimed');
            }
          }
        }
      }
      const ips = await discoverSubdomain(name);
      for (const ip of ips.slice(0, 2)) {
        const ipId = add({ id: 'ip:' + ip, type: 'ip', label: ip, detail: 'DNS address for ' + name, source: 'DNS resolution', confidence: 'high' });
        link('subdomain:' + name, ipId, 'resolves to');
      }
    }));
  }

  const pageInventory = baseScan?.blocked ? [] : pages;
  const home = pageInventory[0] || null;
  const cveFindings = [];
  if (!home) notices.push('The website page inventory was unavailable. DNS and certificate relationships may still be available.');

  let rootPageId = rootId;
  let origin = 'https://' + target.host;
  const pageIds = new Map();
  if (home) {
    origin = new URL(home.url).origin;
    rootPageId = add({ id: 'page:' + origin + '/', type: 'page', label: '/', detail: 'Homepage returned HTTP ' + home.status, source: 'HTTP GET', confidence: 'high', meta: { status: home.status } });
    link(rootId, rootPageId, 'serves');

    const rules = robotsInfo?.disallow || [];
    if (robotsInfo?.found) {
      const robotsId = add({ id: 'robots:' + origin, type: 'metadata', label: 'robots.txt', detail: 'Public crawler policy. Disallowed paths are hints, not access controls; FlawRadar does not fetch them.', source: 'HTTP GET', confidence: 'high' });
      link(rootPageId, robotsId, 'publishes');
      for (const path of rules.slice(0, 20)) {
        const hintId = add({ id: 'path-hint:' + origin + path, type: 'path-hint', label: path, detail: 'Listed as Disallow in robots.txt. Not requested by FlawRadar.', source: 'robots.txt', confidence: 'high' });
        link(robotsId, hintId, 'disallows');
      }
    } else notices.push('robots.txt was not available or did not return a readable text file.');

    for (const sitemapUrl of (robotsInfo?.sitemaps || []).slice(0, 5)) {
      const sitemapId = add({ id: 'sitemap:' + sitemapUrl, type: 'metadata', label: 'sitemap.xml', detail: 'Public URL inventory supplied by the site.', source: 'robots.txt', confidence: 'high' });
      link(rootPageId, sitemapId, 'publishes');
    }
    const fetchedPaths = new Set(pageInventory.map((page) => new URL(page.url).pathname));
    for (const path of (robotsInfo?.paths || []).slice(0, 40)) {
      if (fetchedPaths.has(path)) continue;
      const id = add({ id: 'sitemap-path:' + origin + path, type: 'path-hint', label: path, detail: 'Listed in the sitemap but not fetched within the page limit.', source: 'XML sitemap', confidence: 'high' });
      link(rootPageId, id, 'listed in sitemap');
    }

    const pageRows = [];
    for (const page of pageInventory) {
      const parsed = new URL(page.url);
      if (parsed.origin !== origin || parsed.hostname !== target.host) continue;
      parsed.search = '';
      parsed.hash = '';
      const isHome = page.source === 'homepage' || parsed.pathname === '/';
      const pageId = isHome ? rootPageId : add({
        id: 'page:' + parsed.href,
        type: isInterestingPage(parsed.href) ? 'entry-point' : 'page',
        label: parsed.pathname,
        detail: 'HTTP ' + page.status + ([401, 403].includes(page.status) ? ' · access-controlled response' : ''),
        source: page.source || 'Same-origin page',
        confidence: 'high',
        meta: { status: page.status },
      });
      if (!isHome) link(rootPageId, pageId, 'links to');
      pageIds.set(parsed.href, pageId);
      pageRows.push({ ...page, url: parsed.href, id: pageId });
    }

    if (baseScan?.securityTxt?.found) {
      const secId = add({ id: 'securitytxt:' + origin, type: 'metadata', label: 'security.txt', detail: 'Security contact policy found at ' + baseScan.securityTxt.path + '. Expiry: ' + (baseScan.securityTxt.expires || 'not stated') + '. Contact details are not copied into the graph.', source: 'Well-known metadata', confidence: 'high' });
      link(rootPageId, secId, 'publishes');
    }

    const techs = new Map();
    const packages = [];
    let scriptsRead = 0;
    for (const page of pageRows) {
      const resources = extractResources(page.body, page.url);
      for (const tech of fingerprint(page.body, page.headers || {}, resources)) {
        const key = tech.name.toLowerCase();
        if (!techs.has(key) || (!techs.get(key).version && tech.version)) techs.set(key, tech);
      }
      for (const linkUrl of extractLinks(page.body, page.url)) {
        const linkedId = pageIds.get(linkUrl);
        if (linkedId && linkedId !== page.id) link(page.id, linkedId, 'links to');
      }
      for (const form of extractFormInputs(page.body, page.url)) {
        const formUrl = new URL(form.action);
        const id = add({ id: 'form:' + formUrl.pathname + ':' + form.method, type: 'form', label: formUrl.pathname, detail: 'Form on ' + new URL(page.url).pathname + '; method ' + form.method + '; password field: ' + (form.password ? 'yes' : 'no') + '; fields: ' + (form.fields.join(', ') || 'not identified') + '. FlawRadar does not submit forms.', source: 'Public HTML form', confidence: 'high', meta: { method: form.method, fields: form.fields, password: form.password } });
        link(page.id, id, 'contains form');
      }
      for (const endpoint of extractApiEndpoints(page.body, page.url)) {
        const endpointUrl = new URL(endpoint.url);
        const id = add({ id: 'endpoint:' + endpointUrl.pathname, type: 'endpoint', label: endpointUrl.pathname, detail: 'Endpoint reference in public HTML or inline script. Query parameter names: ' + (endpoint.params.join(', ') || 'none observed') + '. Endpoint was not requested.', source: 'Static page analysis', confidence: 'medium', meta: { parameters: endpoint.params } });
        link(page.id, id, 'references endpoint');
      }
      for (const resource of resources.scripts) {
        if (scriptsRead >= MAX_SCRIPT_FILES) break;
        const scriptUrl = new URL(resource.url);
        if (scriptUrl.origin !== origin) continue;
        scriptsRead += 1;
        const js = await optional(() => fetchText(resource.url, { maxBytes: 90000, timeoutMs: 2500 }));
        if (!js || js.status !== 200 || js.body.length > 90000) continue;
        const contentTechs = fingerprint(js.body, {}, { scripts: [], styles: [], generator: null });
        for (const tech of contentTechs) {
          const key = tech.name.toLowerCase();
          if (!techs.has(key)) techs.set(key, tech);
        }
        for (const endpoint of extractApiEndpoints(js.body, resource.url)) {
          const endpointUrl = new URL(endpoint.url);
          const id = add({ id: 'endpoint:' + endpointUrl.pathname, type: 'endpoint', label: endpointUrl.pathname, detail: 'Endpoint reference in a public JavaScript asset. Parameter names: ' + (endpoint.params.join(', ') || 'not observed') + '. It was not requested.', source: 'Static JavaScript analysis', confidence: 'medium', meta: { parameters: endpoint.params } });
          link(page.id, id, 'script references endpoint');
        }
      }
    }

    for (const tech of techs.values()) {
      const techId = add({ id: 'tech:' + tech.name.toLowerCase(), type: 'technology', label: tech.name + (tech.version ? ' ' + tech.version : ''), detail: tech.evidence, source: 'Passive fingerprint', confidence: tech.version ? 'high' : 'medium', meta: { name: tech.name, version: tech.version } });
      link(rootPageId, techId, 'uses');
      const pkg = packageForTechnology(tech);
      if (pkg) packages.push(pkg);
    }

    if (packages.length) {
      const checked = await optional(() => lookupCves(packages.slice(0, 25)));
      if (checked?.findings?.length) {
        for (const finding of checked.findings) {
          const cveId = finding.cve || finding.osvId;
          cveFindings.push(finding);
          const cveNode = add({ id: 'cve:' + (finding.cve || finding.osvId), type: 'cve', label: cveId, detail: finding.package + '@' + finding.version + ': ' + finding.why, severity: finding.severity, source: 'OSV advisory database', confidence: 'high', meta: { cvss: finding.cvss, cvssBaseScore: finding.cvssBaseScore, epss: finding.epss, kev: finding.kev, fix: finding.fix, osvId: finding.osvId, package: finding.package, version: finding.version, ecosystem: finding.ecosystem, details: finding.advisoryDetails, references: finding.advisoryReferences, affectedRanges: finding.affectedRanges, aliases: finding.aliases, affectedPackages: finding.affectedPackages, published: finding.published, modified: finding.modified } });
          const techId = 'tech:' + (({ jquery: 'jquery', bootstrap: 'bootstrap', angular: 'angularjs', vue: 'vue.js', react: 'react', lodash: 'lodash', moment: 'moment.js', axios: 'axios' })[finding.package] || finding.package);
          link(techId, cveNode, 'has advisory');
        }
      }
      notices.push(...(checked?.notices || []));
    }

    const nvdCandidates = [...techs.values()].filter((tech) => cpeFor(tech)).slice(0, 2);
    const nvdFindings = [];
    for (const tech of nvdCandidates) {
      const nvd = await lookupNvd(tech);
      if (nvd.notice) notices.push(nvd.notice);
      nvdFindings.push(...nvd.findings.map((finding) => ({ ...finding, matchedTechnology: tech.name })));
    }
    if (nvdFindings.length) {
      const ids = nvdFindings.map((finding) => finding.cve);
      const signals = await intelligenceSignals(ids, globalThis.fetch);
      notices.push(...signals.notices);
      for (const finding of nvdFindings) {
        finding.epss = signals.epss.get(finding.cve) || null;
        finding.kev = signals.kev.get(finding.cve) || null;
        cveFindings.push(finding);
        const cveNode = add({ id: 'cve:' + (finding.cve || finding.osvId), type: 'cve', label: finding.cve, detail: finding.package + '@' + finding.version + ': ' + finding.why, severity: finding.severity, source: 'NVD CPE version match', confidence: 'high', meta: { cvss: finding.cvss, cvssBaseScore: finding.cvssBaseScore, epss: finding.epss, kev: finding.kev, fix: finding.fix, osvId: finding.osvId, package: finding.package, version: finding.version, ecosystem: finding.ecosystem, details: finding.advisoryDetails, references: finding.advisoryReferences, affectedRanges: finding.affectedRanges, aliases: finding.aliases, cpe: finding.affectedPackages?.[0]?.name } });
        link('tech:' + finding.matchedTechnology.toLowerCase(), cveNode, 'matches CPE advisory');
      }
    }
  } else {
    notices.push('robots.txt and sitemap relationships could not be mapped because the homepage was unavailable.');
  }

  for (const finding of baseScan?.findings || []) {
    const id = add({ id: 'finding:' + finding.ruleId + ':' + finding.title, type: 'finding', label: finding.title, detail: (finding.why || '') + ' Fix: ' + (finding.fix || 'Review the affected configuration.'), severity: severityOf(finding), source: 'FlawRadar checks', confidence: finding.confidence === 'high' ? 'high' : 'medium', meta: { ruleId: finding.ruleId, fix: finding.fix, location: finding.file || finding.path || '' } });
    link(rootId, id, 'has finding');
  }

  for (const finding of cveFindings) {
    finding.priority = calculateRiskPriority(finding, { exposure: 1 });
    const node = graph.byId.get('cve:' + (finding.cve || finding.osvId));
    if (node) node.meta = { ...node.meta, priority: finding.priority };
  }

  if (baseScan?.blocked) notices.push('The website returned a block page during the baseline checks; some results may be incomplete.');
  if (baseScan?.findings?.length === 0) notices.push('No baseline security findings were reported. This is not proof that the website is secure.');
  const counts = graph.nodes.reduce((acc, item) => {
    acc[item.type] = (acc[item.type] || 0) + 1;
    if (item.severity !== 'info') acc[item.severity] = (acc[item.severity] || 0) + 1;
    return acc;
  }, {});
  return {
    host: target.host,
    rootDomain: root,
    generatedAt: new Date().toISOString(),
    nodes: graph.nodes,
    edges: graph.edges,
    counts,
    cveFindings,
    summary: {
      assets: graph.nodes.length,
      relationships: graph.edges.length,
      pages: (counts.page || 0) + (counts['entry-point'] || 0),
      subdomains: counts.subdomain || 0,
      technologies: counts.technology || 0,
      vulnerabilities: counts.cve || 0,
      critical: graph.nodes.filter((item) => item.severity === 'critical').length,
      high: graph.nodes.filter((item) => item.severity === 'high').length,
      networkHops: networkPath?.hops?.length || 0,
      highestPriority: cveFindings.reduce((best, item) => Math.max(best, item.priority?.score ?? 0), 0),
    },
    riskModel: { id: 'weighted-priority-v1', description: 'Prioritisation heuristic using CVSS (40%), EPSS (30%), CISA KEV (20%) and public exposure (10%); missing signals are omitted and remaining weights renormalised. Confidence adjusts the final score. This is not a probability of compromise.' },
    networkPath,
    baseline: baseScan ? { score: baseScan.score, grade: baseScan.grade, findings: baseScan.findings || [], blocked: Boolean(baseScan.blocked) } : null,
    notices: unique(notices),
  };
}
