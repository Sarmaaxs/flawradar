import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import zlib from 'node:zlib';
import { config, userAgent } from '../config.js';
import { AppError } from '../errors.js';
import { resolvePublic } from './net.js';

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/** Choose the address to connect to. If an egress IP is set, match its family. */
export function pickAddress(records) {
  if (config.egressIp) {
    const family = net.isIP(config.egressIp);
    const match = records.find((r) => r.family === family);
    if (match) return match;
  }
  return records[0];
}

function decoded(res) {
  const enc = String(res.headers['content-encoding'] || '').toLowerCase();
  if (enc === 'gzip' || enc === 'x-gzip') return res.pipe(zlib.createGunzip());
  if (enc === 'br') return res.pipe(zlib.createBrotliDecompress());
  if (enc === 'deflate') return res.pipe(zlib.createInflate());
  return res;
}

/**
 * One HTTP request to an address we already checked. The connection is pinned
 * to that address through a custom lookup, so a second DNS answer cannot
 * redirect it somewhere else (DNS rebinding).
 */
function requestOnce(url, { method, headers, maxBytes, timeoutMs, address }) {
  return new Promise((resolve, reject) => {
    const secure = url.protocol === 'https:';
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    const options = {
      hostname,
      port: url.port || (secure ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method,
      agent: false,
      headers: {
        'User-Agent': userAgent(),
        Accept: '*/*',
        'Accept-Encoding': 'gzip, br',
        Connection: 'close',
        ...headers,
      },
      localAddress: config.egressIp || undefined,
      lookup: (_host, opts, cb) => {
        if (opts && opts.all) cb(null, [{ address: address.address, family: address.family }]);
        else cb(null, address.address, address.family);
      },
    };
    if (secure) {
      // We want to report on bad certificates, not fail on them.
      options.rejectUnauthorized = false;
      if (!net.isIP(hostname)) options.servername = hostname;
    }

    const started = Date.now();
    let settled = false;
    let req;
    const timer = setTimeout(() => {
      req?.destroy(Object.assign(new Error('Timed out'), { code: 'ETIMEDOUT' }));
    }, timeoutMs);
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };

    req = (secure ? https : http).request(options, (res) => {
      const tlsInfo = secure
        ? {
            authorized: Boolean(res.socket.authorized),
            authError: res.socket.authorizationError ? String(res.socket.authorizationError) : null,
            protocol: res.socket.getProtocol?.() || null,
          }
        : null;
      const stream = decoded(res);
      const chunks = [];
      let size = 0;
      let truncated = false;
      const done = () =>
        settle(resolve, {
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          truncated,
          tls: tlsInfo,
          ms: Date.now() - started,
        });
      stream.on('data', (chunk) => {
        if (truncated) return;
        size += chunk.length;
        if (size > maxBytes) {
          truncated = true;
          chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
          res.destroy();
          done();
          return;
        }
        chunks.push(chunk);
      });
      stream.on('end', done);
      stream.on('error', done);
      res.on('error', done);
      res.on('close', () => {
        if (!res.complete) done();
      });
    });
    req.on('error', (err) => settle(reject, err));
    req.end();
  });
}

function allowedHop(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  if (url.port && !config.allowPrivate) return false;
  return true;
}

/**
 * Fetch a URL with redirects followed by hand. Every hop is checked against
 * the public-address rules before we connect.
 *
 * Throws AppError when the first URL is not allowed. A redirect to somewhere
 * not allowed is not followed; the redirect response itself is returned with
 * `blockedRedirect` set.
 */
export async function fetchUrl(
  input,
  {
    method = 'GET',
    headers = {},
    follow = true,
    maxRedirects = 5,
    maxBytes = config.maxPageBytes,
    timeoutMs = config.requestTimeoutMs,
  } = {},
) {
  let url = new URL(input);
  if (!allowedHop(url)) {
    throw new AppError(400, 'invalid_url', 'That address cannot be scanned.');
  }
  const redirects = [];
  for (let hop = 0; ; hop += 1) {
    let address;
    try {
      address = pickAddress(await resolvePublic(url.hostname));
    } catch (err) {
      if (hop === 0) throw err;
      const last = redirects[redirects.length - 1];
      return { ...last.response, url: last.from, redirects: redirects.slice(0, -1), blockedRedirect: url.href };
    }
    const response = await requestOnce(url, { method, headers, maxBytes, timeoutMs, address });
    const location = response.headers.location;
    if (follow && REDIRECT_STATUS.has(response.status) && location) {
      let next;
      try {
        next = new URL(location, url);
      } catch {
        return { ...response, url: url.href, redirects, address: address.address };
      }
      if (!allowedHop(next) || hop >= maxRedirects) {
        return { ...response, url: url.href, redirects, address: address.address, blockedRedirect: next.href };
      }
      redirects.push({ from: url.href, to: next.href, status: response.status, response });
      url = next;
      continue;
    }
    return {
      ...response,
      url: url.href,
      redirects: redirects.map(({ from, to, status }) => ({ from, to, status })),
      address: address.address,
    };
  }
}
