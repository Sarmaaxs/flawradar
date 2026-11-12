import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { config, userAgent } from './config.js';
import { AppError } from './errors.js';
import * as db from './db.js';
import { Limiter } from './ratelimit.js';
import { parseTarget, resolvePublic } from './scanner/net.js';
import { listChecks } from './scanner/checks.js';
import { buildFixConfig } from './scanner/fixes.js';
import { startScan } from './scans.js';
import { checkOwnership, instructions } from './verify.js';

const PUBLIC = path.join(config.root, 'public');
const ID = '[a-f0-9]{24}';

const scanLimiter = new Limiter({ limit: config.scansPerHour, windowMs: 3_600_000 });
const verifyLimiter = new Limiter({ limit: config.verifyChecksPerHour, windowMs: 3_600_000 });

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
  '/checks': 'checks.html',
  '/about': 'about.html',
};

// The site follows the advice it gives.
function securityHeaders() {
  const h = {
    'Content-Security-Policy': [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
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

async function readJson(req, limit = 4096) {
  if (!String(req.headers['content-type'] || '').startsWith('application/json')) {
    throw new AppError(415, 'unsupported_media_type', 'Send the request body as JSON.');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new AppError(413, 'too_large', 'The request body is too large.');
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new Error('not an object');
    return body;
  } catch {
    throw new AppError(400, 'bad_json', 'The request body is not a valid JSON object.');
  }
}

async function serveFile(req, res, relative, { cache = 'public, max-age=300', extra = {} } = {}) {
  const full = path.resolve(PUBLIC, `.${path.sep}${relative}`);
  if (!full.startsWith(PUBLIC + path.sep) || relative.includes('\0')) throw new AppError(404, 'not_found', 'Not found.');
  let stat;
  try {
    stat = await fs.promises.stat(full);
  } catch {
    throw new AppError(404, 'not_found', 'Not found.');
  }
  if (!stat.isFile()) throw new AppError(404, 'not_found', 'Not found.');
  res.writeHead(200, {
    ...securityHeaders(),
    'Content-Type': MIME[path.extname(full)] || 'application/octet-stream',
    'Content-Length': stat.size,
    'Cache-Control': cache,
    ...extra,
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(full).pipe(res);
}

// ------------------------------------------------------------------ API routes

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
    retentionDays: config.retentionDays,
  };
}

const api = {
  health(req, res) {
    sendJson(res, 200, { ok: true, version: config.version });
  },

  scanner(req, res) {
    sendJson(res, 200, {
      name: 'Wsec',
      version: config.version,
      userAgent: userAgent(),
      ips: config.publicIps,
      contact: config.contact || null,
      baseUrl: config.baseUrl,
    });
  },

  checks(req, res) {
    sendJson(res, 200, { checks: listChecks() });
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
    const target = parseTarget(body.url);
    await resolvePublic(target.host);

    const hostScans = db.countHostScansSince(target.host, Date.now() - 3_600_000);
    if (hostScans >= config.scansPerHostPerHour) {
      throw new AppError(429, 'host_rate_limited', `${target.host} was scanned ${hostScans} times in the last hour. Try again later.`, {
        retryAfter: 600,
      });
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
    const id = startScan(target, { deep });
    sendJson(res, 202, { id, status: 'queued' }, { Location: `/report/${id}` });
  },

  getScan(req, res, [id]) {
    const row = db.getScan(id);
    if (!row) throw new AppError(404, 'not_found', 'No report with that id. It may have been deleted.');
    sendJson(res, 200, shapeScan(row));
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
    sendText(res, 200, text, { 'Content-Disposition': `attachment; filename="wsec-${server}.${ext}"` });
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
  ['GET', /^\/api\/checks$/, api.checks],
  ['POST', /^\/api\/scans$/, api.createScan],
  ['GET', new RegExp(`^/api/scans/(${ID})$`), api.getScan],
  ['GET', new RegExp(`^/api/scans/(${ID})/fix$`), api.fix],
  ['POST', /^\/api\/verify$/, api.verify],
  ['POST', /^\/api\/verify\/check$/, api.verifyCheck],
];

async function route(req, res) {
  let url;
  try {
    url = new URL(req.url, 'http://wsec.local');
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
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  return server;
}
