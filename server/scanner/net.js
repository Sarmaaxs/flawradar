import net from 'node:net';
import dns from 'node:dns/promises';
import { config } from '../config.js';
import { AppError } from '../errors.js';

// Ranges the scanner must never connect to. Without this, a scan request
// is a way to make our server talk to its own network.
//
// IPv4 and IPv6 live in separate lists on purpose: Node treats an IPv4 address
// as an IPv4-mapped IPv6 address when it is checked against an IPv6 rule, so a
// shared list would make rules like ::ffff:0:0/96 match every IPv4 address.
const reserved4 = new net.BlockList();
for (const [addr, bits] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  reserved4.addSubnet(addr, bits, 'ipv4');
}

// Only global unicast IPv6 (2000::/3) is allowed at all, which already rules out
// loopback, link-local, unique-local, multicast and IPv4-mapped addresses.
// What is left to exclude are special-purpose blocks inside 2000::/3.
const globalV6 = new net.BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
const reserved6 = new net.BlockList();
for (const [addr, bits] of [
  ['2001::', 23], // IETF protocol assignments, Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4, embeds an IPv4 address
  ['3fff::', 20], // documentation
]) {
  reserved6.addSubnet(addr, bits, 'ipv6');
}

export function isPublicIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return !reserved4.check(ip, 'ipv4');
  if (family === 6) return globalV6.check(ip, 'ipv6') && !reserved6.check(ip, 'ipv6');
  return false;
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const INTERNAL_SUFFIX = /(^|\.)(localhost|local|internal|intranet|lan|home|corp)$/;

// Honour operator-maintained opt-out domains, including all subdomains.
export function isOptedOut(hostname) {
  const host = String(hostname || '').replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!host) return false;
  return config.blockedHosts.some((blocked) => host === blocked || host.endsWith(`.${blocked}`));
}

/**
 * Turn what a person typed into a scan target.
 * Accepts "example.com", "https://example.com/some/path" and so on.
 * Only the host is kept; scans always start at the home page.
 */
export function parseTarget(input) {
  if (typeof input !== 'string') {
    throw new AppError(400, 'invalid_url', 'Enter a website address.');
  }
  let raw = input.trim();
  if (!raw || raw.length > 300) {
    throw new AppError(400, 'invalid_url', 'Enter a website address.');
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new AppError(400, 'invalid_url', 'That does not look like a web address.');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new AppError(400, 'invalid_url', 'Only http and https addresses can be scanned.');
  }
  if (u.username || u.password) {
    throw new AppError(400, 'invalid_url', 'Remove the user name and password from the address.');
  }

  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  const family = net.isIP(host);

  if (family && !config.allowPrivate) {
    throw new AppError(400, 'invalid_url', 'Enter a host name, not an IP address.');
  }
  if (!family) {
    const labels = host.split('.');
    const valid = host.length <= 253 && labels.every((l) => LABEL.test(l));
    if (!valid) throw new AppError(400, 'invalid_url', 'That is not a valid host name.');
    if (!config.allowPrivate) {
      if (labels.length < 2 || INTERNAL_SUFFIX.test(host)) {
        throw new AppError(403, 'blocked_target', 'FlawRadar only scans public host names.');
      }
    }
  }
  if (u.port && !config.allowPrivate) {
    throw new AppError(400, 'invalid_url', 'Only the standard ports (80 and 443) are scanned.');
  }

  const port = u.port ? Number(u.port) : null;
  return {
    input: u.href,
    host,
    hostUrl: family === 6 ? `[${host}]` : host,
    isIp: family !== 0,
    scheme: u.protocol.slice(0, -1),
    port,
  };
}

/**
 * Resolve a host name and refuse anything that points at a non-public address.
 * Returns address records, IPv4 first.
 */
export async function resolvePublic(hostname) {
  const bare = hostname.replace(/^\[|\]$/g, '');
  if (isOptedOut(bare)) {
    throw new AppError(403, 'opted_out', `${bare} has opted out of FlawRadar scans.`);
  }
  if (net.isIP(bare)) {
    if (!config.allowPrivate && !isPublicIp(bare)) {
      throw new AppError(403, 'blocked_target', 'FlawRadar only scans public addresses.');
    }
    return [{ address: bare, family: net.isIP(bare) }];
  }
  let records;
  try {
    records = await dns.lookup(bare, { all: true, verbatim: true });
  } catch (err) {
    throw new AppError(422, 'dns_failed', `Could not find ${bare}. Check the spelling.`, { cause: err.code });
  }
  if (!records.length) {
    throw new AppError(422, 'dns_failed', `${bare} has no address records.`);
  }
  if (!config.allowPrivate) {
    for (const r of records) {
      if (!isPublicIp(r.address)) {
        throw new AppError(
          403,
          'blocked_target',
          `${bare} points at a private or reserved address. FlawRadar only scans public hosts.`,
        );
      }
    }
  }
  return records.sort((a, b) => a.family - b.family);
}
