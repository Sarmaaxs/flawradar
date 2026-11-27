import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { config } from './config.js';
import { AppError } from './errors.js';
import { diffScans } from './scanner/diff.js';
import * as db from './db.js';
import { Limiter } from './ratelimit.js';
import { parseTarget, resolvePublic } from './scanner/net.js';
import { buildFixConfig } from './scanner/fixes.js';
import { startScan } from './scans.js';
import * as watch from './watch.js';
import { checkOwnership, instructions } from './verify.js';
import { checkAllow } from './allow.js';
import { analyzeFiles } from './source/analyze.js';
import { lookupCves } from './source/cves.js';
import { readZip } from './source/zip.js';
import { runScan } from './scanner/scan.js';
import { runDomainIntelligence } from './scanner/intelligence.js';
import { traceVerifiedHost } from './scanner/route.js';

const PUBLIC = path.join(config.root, 'public');
const ID = '[a-f0-9]{24}';

const scanLimiter = new Limiter({ limit: config.scansPerHour, windowMs: 3_600_000 });
const verifyLimiter = new Limiter({ limit: config.verifyChecksPerHour, windowMs: 3_600_000 });
const watchLimiter = new Limiter({ limit: config.watchSignupsPerHour, windowMs: 3_600_000 });
const sourceLimiter = new Limiter({ limit: config.sourcePerHour, windowMs: 3_600_000 });
const intelligenceLimiter = new Limiter({ limit: 2, windowMs: 3_600_000 });

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
};

const PAGES = {
  '/': 'index.html',
  '/whitelist': 'whitelist.html',
  '/verify': 'verify.html',
  '/source': 'source.html',
  '/cve': 'cve.html',
  '/intel': 'intel.html',
  '/intelligence': 'intel.html',
  '/about': 'about.html',
  '/terms': 'terms.html',
  '/acceptable-use': 'acceptable-use.html',
  '/privacy': 'privacy.html',
  '/watch': 'watch.html',
  '/watch/confirm': 'watch.html',
  '/watch/stop': 'watch.html',
};

// The site follows the advice it gives.
function securityHeaders() {
  const h = {
    'Content-Security-Policy': [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "frame-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
  if (config.baseUrl.startsWith('https://')) {
    h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }
  return h;
}

function clientIp(req) {
  if (config.trustProxy) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return req.socket.remoteAddress || 'unknown';
}

function sendJson(res, status, body, extra = {}) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    ...securityHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(data);
}

function sendText(res, status, text, extra = {}) {
  res.writeHead(status, {
    ...securityHeaders(),
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(text);
}

async function readBody(req, limit) {
  const declared = Number(req.headers['content-length']);
  if (declared > limit) {
    throw new AppError(413, 'too_large', `The upload is too large. The limit is ${Math.round(limit / 1_048_576)} MB.`);
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      throw new AppError(413, 'too_large', `The upload is too large. The limit is ${Math.round(limit / 1_048_576)} MB.`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(req, limit = 4096) {
  if (!String(req.headers['content-type'] || '').startsWith('application/json')) {
    throw new AppError(415, 'unsupported_media_type', 'Send the request body as JSON.');
  }
  const raw = await readBody(req, limit);
  try {
    const body = JSON.parse(raw.toString('utf8'));
    if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new Error('not an object');
    return body;
  } catch {
    throw new AppError(400, 'bad_json', 'The request body is not a valid JSON object.');
  }
}

async function serveFile(req, res, relative, { cache = 'no-cache', extra = {}, root = PUBLIC } = {}) {
  const full = path.resolve(root, `.${path.sep}${relative}`);
  if (!full.startsWith(root + path.sep) || relative.includes('\0')) throw new AppError(404, 'not_found', 'Not found.');
  let stat;
  try {
    stat = await fs.promises.stat(full);
  } catch {
    throw new AppError(404, 'not_found', 'Not found.');
  }
  if (!stat.isFile()) throw new AppError(404, 'not_found', 'Not found.');
  // no-cache means "ask me every time": the browser keeps a copy but revalidates it, and gets a
  // cheap 304 when the file did not change. Updated CSS and JS show up on the next load.
  const etag = `W/"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
  const headers = {
    ...securityHeaders(),
    'Cache-Control': cache,
    ETag: etag,
    'Last-Modified': stat.mtime.toUTCString(),
    ...extra,
  };
  if (req.headers['if-none-match'] === etag) {
    res.writeHead(304, headers);
    return res.end();
  }
  res.writeHead(200, {
    ...headers,
    'Content-Type': MIME[path.extname(full)] || 'application/octet-stream',
    'Content-Length': stat.size,
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(full).pipe(res);
}

// ------------------------------------------------------------------ API routes

const sha256 = (text) => crypto.createHash('sha256').update(String(text)).digest('hex');

function shapeScan(row) {
  const result = row.result ? JSON.parse(row.result) : null;
  const previous = db.previousScan(row.host, row.id, row.created_at);
  return {
    id: row.id,
    host: row.host,
    deep: Boolean(row.deep),
    status: row.status,
    progress: JSON.parse(row.progress),
    error: row.error,
    createdAt: row.created_at,
    finishedAt: row.finished_at,
    result,
    previous: previous
      ? { id: previous.id, score: previous.score, grade: previous.grade, createdAt: previous.created_at }
      : null,
    changes: previous ? diffScans(safeParse(previous.result), result) : null,
    retentionDays: config.retentionDays,
  };
}

function safeParse(text) {
  try { return text ? JSON.parse(text) : null; } catch { return null; }
}


// People must confirm authorization and accept the current terms before anything is scanned.
// The client sends the version it showed them; a stale page is refused so it cannot accept old text.
function requireTerms(version) {
  if (version !== config.termsVersion) {
    throw new AppError(
      400,
      'terms_required',
      'Confirm that you are authorized to test this and that you accept the Terms of Service, then try again. If you already did, reload the page: the terms may have changed.',
    );
  }
}

function limitSource(req) {
  const hit = sourceLimiter.hit(clientIp(req));
  if (!hit.ok) {
    throw new AppError(429, 'rate_limited', `Too many source checks from your address. Try again in ${Math.ceil(hit.retryAfter / 60)} minutes.`, {
      retryAfter: hit.retryAfter,
    });
  }
}

const api = {
  health(req, res) {
    // For uptime monitors: 200 when the app and its database answer, 503 otherwise.
    let dbOk = true;
    try {
      db.stats();
    } catch {
      dbOk = false;
    }
    sendJson(res, dbOk ? 200 : 503, {
      ok: dbOk,
    });
  },

  scanner(req, res) {
    sendJson(res, 200, {
      // Public configuration is deliberately limited to details required by the UI and legal pages.
      ips: config.publicIps,
      contact: config.contact || null,
      termsVersion: config.termsVersion,
      watches: { enabled: config.mail.enabled, intervalHours: config.watchIntervalHours },
      legal: {
        entity: config.legal.entity || null,
        email: config.legal.email || null,
        law: config.legal.law || null,
        hosting: config.legal.hosting || null,
        logRetention: config.legal.logRetention || null,
      },
      limits: { retentionDays: config.retentionDays },
    });
  },



  async domainIntelligence(req, res) {
    const hit = intelligenceLimiter.hit(clientIp(req));
    if (!hit.ok) throw new AppError(429, 'rate_limited', 'Too many domain investigations. Try again later.', { retryAfter: hit.retryAfter });
    const body = await readJson(req, 8192);
    requireTerms(body.terms);
    const target = parseTarget(body.host);
    await resolvePublic(target.host);
    const pageEvidence = [];
    let robotsInfo = null;
    const [baseline, networkPath] = await Promise.all([
      runScan(target, {
        deep: false,
        onPage: (page) => pageEvidence.push(page),
        onRobots: (info) => { robotsInfo = info; },
      }),
      traceVerifiedHost(target.host),
    ]);
    const result = await runDomainIntelligence(target, { baseScan: baseline, pages: pageEvidence, robotsInfo, networkPath });
    db.storeCveIntel(result.cveFindings || []);
    delete result.cveFindings;
    sendJson(res, 200, result);
  },

  async createScan(req, res) {
    const ip = clientIp(req);
    const limit = scanLimiter.hit(ip);
    if (!limit.ok) {
      throw new AppError(
        429,
        'rate_limited',
        `Too many scans from your address. Try again in ${Math.ceil(limit.retryAfter / 60)} minutes.`,
        { retryAfter: limit.retryAfter },
      );
    }
    const body = await readJson(req);
    requireTerms(body.terms);
    const target = parseTarget(body.url);
    await resolvePublic(target.host);

    // Optional owner signal: higher per-host rate limit, shown on the report.
    let allow = null;
    try {
      const a = await checkAllow(target);
      if (a.allowed) allow = { method: a.method, contact: a.contact || null };
    } catch {
      /* allow check is best-effort; a DNS failure must not block the scan */
    }

    const hostLimit = allow ? config.scansPerHostAllowedPerHour : config.scansPerHostPerHour;
    const hostScans = db.countHostScansSince(target.host, Date.now() - 3_600_000);
    if (hostScans >= hostLimit) {
      throw new AppError(
        429,
        'host_rate_limited',
        allow
          ? `${target.host} was scanned ${hostScans} times in the last hour (allow-listed limit is ${hostLimit}). Try again later.`
          : `${target.host} was scanned ${hostScans} times in the last hour. Try again later.`,
        { retryAfter: 600 },
      );
    }

    const deep = body.deep === true;
    if (deep) {
      const proof = await checkOwnership(target);
      if (!proof.verified) {
        throw new AppError(403, 'needs_verification', 'Deep scans need proof that you control this host.', {
          host: target.host,
          tried: proof.tried,
        });
      }
    }
    // The person who starts a scan gets a secret that lets them delete the report. Only its hash is
    // stored. Someone who merely has the report link can read it but cannot delete it.
    const deleteToken = crypto.randomBytes(24).toString('hex');
    const id = startScan(target, { deep, termsVersion: body.terms, allow, deleteHash: sha256(deleteToken) });
    sendJson(res, 202, { id, status: 'queued', allow: allow || undefined, deleteToken }, { Location: `/report/${id}` });
  },

  getScan(req, res, [id]) {
    const row = db.getScan(id);
    if (!row) throw new AppError(404, 'not_found', 'No report with that id. It may have been deleted.');
    sendJson(res, 200, shapeScan(row));
  },

  async createWatch(req, res) {
    const hit = watchLimiter.hit(clientIp(req));
    if (!hit.ok) {
      throw new AppError(429, 'rate_limited', `Too many sign-ups from your address. Try again in ${Math.ceil(hit.retryAfter / 60)} minutes.`, { retryAfter: hit.retryAfter });
    }
    const body = await readJson(req);
    requireTerms(body.terms);
    const done = await watch.subscribe({ url: body.url, email: body.email });
    sendJson(res, 202, { ok: true, host: done.host, message: 'If the proof is in place, a confirmation link is on its way. It works once the address is confirmed.' });
  },

  async confirmWatch(req, res) {
    const body = await readJson(req);
    sendJson(res, 200, watch.confirm(body.id, body.s));
  },

  async stopWatch(req, res) {
    const body = await readJson(req);
    sendJson(res, 200, watch.stop(body.id, body.s));
  },

  deleteScan(req, res, [id]) {
    const row = db.getScan(id);
    if (!row) throw new AppError(404, 'not_found', 'No report with that id. It may already be deleted.');
    const token = String(req.headers['x-flawradar-delete'] || '');
    const stored = row.delete_hash || '';
    const given = sha256(token);
    const ok = token && stored.length === given.length && crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(given));
    if (!ok) {
      throw new AppError(403, 'not_yours', 'Only the browser that started this scan can delete it. Ask the person who ran it, or email the contact on the Privacy page.');
    }
    db.deleteScan(id);
    sendJson(res, 200, { deleted: true });
  },

  fix(req, res, [id], url) {
    const row = db.getScan(id);
    if (!row || !row.result) throw new AppError(404, 'not_found', 'No finished report with that id.');
    const server = url.searchParams.get('server');
    if (!['nginx', 'apache', 'express'].includes(server)) {
      throw new AppError(400, 'bad_server', 'server must be nginx, apache or express.');
    }
    const result = JSON.parse(row.result);
    const text = buildFixConfig(result.findings, server, row.host);
    if (!text) throw new AppError(404, 'nothing_to_fix', 'No header or protocol fixes for that server in this report.');
    const ext = { nginx: 'conf', apache: 'conf', express: 'js' }[server];
    sendText(res, 200, text, { 'Content-Disposition': `attachment; filename="flawradar-${server}.${ext}"` });
  },



  // Source code arrives as JSON: { files: [{ path, content }] }. It is analysed
  // in memory and thrown away. Nothing about it is stored.
  async source(req, res) {
    limitSource(req);
    const body = await readJson(req, config.maxSourceJsonBytes);
    requireTerms(body.terms);
    if (!Array.isArray(body.files) || !body.files.length) {
      throw new AppError(400, 'no_files', 'Add at least one file.');
    }
    if (body.files.length > config.maxSourceFiles) {
      throw new AppError(413, 'too_many_files', `That is ${body.files.length} files. The limit is ${config.maxSourceFiles}. Drop only the source folders.`);
    }
    const files = [];
    let bytes = 0;
    for (const f of body.files) {
      if (!f || typeof f.path !== 'string' || typeof f.content !== 'string') {
        throw new AppError(400, 'bad_files', 'Each file needs a path and content, both as text.');
      }
      bytes += f.content.length;
      if (bytes > config.maxSourceTotalBytes) {
        throw new AppError(413, 'too_large', `Too much source. The limit is ${Math.round(config.maxSourceTotalBytes / 1_048_576)} MB of text.`);
      }
      files.push({ path: f.path.slice(0, 500), content: f.content });
    }
    sendJson(res, 200, await analyzeFiles(files, { maxFileBytes: config.maxFileBytes }));
  },

  // Package-only advisory relay. The source-analysis engine itself runs server-side.
  async cves(req, res) {
    limitSource(req);
    const body = await readJson(req, 256 * 1024);
    requireTerms(body.terms);
    const ecosystems = new Set(['npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'NuGet', 'RubyGems', 'Packagist']);
    if (!Array.isArray(body.packages) || !body.packages.length || body.packages.length > 1200) {
      throw new AppError(400, 'bad_packages', 'Send between 1 and 1200 packages.');
    }
    const packages = [];
    for (const p of body.packages) {
      const ok = p && typeof p.name === 'string' && typeof p.version === 'string' && typeof p.file === 'string' &&
        ecosystems.has(p.ecosystem) && p.name.length <= 214 && p.version.length <= 100;
      if (!ok) throw new AppError(400, 'bad_packages', 'Each package needs a supported ecosystem, name, resolved version and file.');
      packages.push({ name: p.name, version: p.version, ecosystem: p.ecosystem, file: p.file.slice(0, 500), line: Number.isInteger(p.line) ? p.line : 1 });
    }
    const result = await lookupCves(packages);
    db.storeCveIntel(result.findings);
    sendJson(res, 200, result);
  },

  async sourceZip(req, res) {
    limitSource(req);
    requireTerms(req.headers['x-flawradar-terms']);
    const type = String(req.headers['content-type'] || '');
    if (!/^application\/(?:zip|x-zip-compressed|octet-stream)/.test(type)) {
      throw new AppError(415, 'unsupported_media_type', 'Send the zip file as the request body.');
    }
    const buffer = await readBody(req, config.maxZipBytes);
    const { files, skipped, notices } = readZip(buffer, {
      maxEntries: config.maxSourceFiles * 4,
      maxFileBytes: config.maxFileBytes,
      maxTotalBytes: config.maxSourceTotalBytes,
    });
    sendJson(res, 200, await analyzeFiles(files, { skipped, notices, maxFileBytes: config.maxFileBytes }));
  },

  async verify(req, res) {
    const body = await readJson(req);
    const target = parseTarget(body.host);
    sendJson(res, 200, instructions(target));
  },

  async verifyCheck(req, res) {
    const limit = verifyLimiter.hit(clientIp(req));
    if (!limit.ok) {
      throw new AppError(429, 'rate_limited', 'Too many verification checks. Try again later.', {
        retryAfter: limit.retryAfter,
      });
    }
    const body = await readJson(req);
    const target = parseTarget(body.host);
    await resolvePublic(target.host);
    const proof = await checkOwnership(target);
    sendJson(res, 200, { host: target.host, ...proof });
  },
};

const routes = [
  ['GET', /^\/api\/health$/, api.health],
  ['GET', /^\/api\/scanner$/, api.scanner],
  ['POST', /^\/api\/intelligence$/, api.domainIntelligence],
  ['POST', /^\/api\/scans$/, api.createScan],
  ['GET', new RegExp(`^/api/scans/(${ID})$`), api.getScan],
  ['DELETE', new RegExp(`^/api/scans/(${ID})$`), api.deleteScan],
  ['GET', new RegExp(`^/api/scans/(${ID})/fix$`), api.fix],
  ['POST', /^\/api\/source$/, api.source],
  ['POST', /^\/api\/source\/zip$/, api.sourceZip],
  ['POST', /^\/api\/cves$/, api.cves],
  ['POST', /^\/api\/watch$/, api.createWatch],
  ['POST', /^\/api\/watch\/confirm$/, api.confirmWatch],
  ['POST', /^\/api\/watch\/stop$/, api.stopWatch],
  ['POST', /^\/api\/verify$/, api.verify],
  ['POST', /^\/api\/verify\/check$/, api.verifyCheck],
];

async function route(req, res) {
  let url;
  try {
    url = new URL(req.url, 'http://flawradar.local');
  } catch {
    throw new AppError(400, 'bad_request', 'Bad request.');
  }
  const pathname = url.pathname;
  const isRead = req.method === 'GET' || req.method === 'HEAD';

  if (pathname.startsWith('/api/')) {
    const matching = routes.filter(([, pattern]) => pattern.test(pathname));
    if (!matching.length) throw new AppError(404, 'not_found', 'No such API route.');
    const method = req.method === 'HEAD' ? 'GET' : req.method;
    const hit = matching.find(([m]) => m === method);
    if (!hit) {
      throw new AppError(405, 'method_not_allowed', 'Method not allowed.', { allow: matching.map(([m]) => m).join(', ') });
    }
    const params = pathname.match(hit[1]).slice(1);
    return hit[2](req, res, params, url);
  }

  if (!isRead) throw new AppError(405, 'method_not_allowed', 'Method not allowed.', { allow: 'GET, HEAD' });

  if (PAGES[pathname]) return serveFile(req, res, PAGES[pathname], { cache: 'no-cache' });
  if (new RegExp(`^/report/${ID}$`).test(pathname)) {
    return serveFile(req, res, 'report.html', { cache: 'no-cache', extra: { 'X-Robots-Tag': 'noindex' } });
  }
  if (pathname === '/robots.txt') return serveFile(req, res, 'robots.txt');
  if (pathname.startsWith('/assets/')) {
    let decoded;
    try {
      decoded = decodeURIComponent(pathname.slice(1));
    } catch {
      throw new AppError(400, 'bad_request', 'Bad request.');
    }
    return serveFile(req, res, decoded);
  }
  throw new AppError(404, 'not_found', 'Not found.');
}

function fail(req, res, err) {
  if (res.headersSent) return res.end();
  const known = err instanceof AppError;
  if (!known) console.error('unhandled error', err);
  const status = known ? err.status : 500;
  const extra = {};
  if (known && err.extra?.retryAfter) extra['Retry-After'] = String(err.extra.retryAfter);
  if (known && err.extra?.allow) extra.Allow = err.extra.allow;
  const wantsHtml = !req.url.startsWith('/api/') && String(req.headers.accept || '').includes('text/html');
  if (wantsHtml) return sendText(res, status, known ? err.message : 'Something went wrong.', extra);
  const { retryAfter, allow, ...detail } = known ? err.extra || {} : {};
  sendJson(
    res,
    status,
    { error: { code: known ? err.code : 'internal_error', message: known ? err.message : 'Something went wrong.', ...detail } },
    extra,
  );
}

export function createServer() {
  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    res.on('finish', () => {
      if (!config.quiet) console.log(`${req.method} ${req.url.split('?')[0]} ${res.statusCode} ${Date.now() - started}ms`);
    });
    try {
      await route(req, res);
    } catch (err) {
      fail(req, res, err);
    }
  });
  server.requestTimeout = 60_000; // source uploads can be several MB
  server.headersTimeout = 10_000;
  return server;
}