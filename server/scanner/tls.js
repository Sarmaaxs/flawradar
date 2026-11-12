import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { config } from '../config.js';

// Errors that mean "the server said no to this protocol version".
const REFUSED = new Set([
  'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION',
  'ERR_SSL_UNSUPPORTED_PROTOCOL',
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'ERR_SSL_TLSV1_ALERT_INSUFFICIENT_SECURITY',
  'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  'ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR',
  'ERR_SSL_NO_SHARED_CIPHER',
  'ERR_SSL_VERSION_TOO_LOW',
  'ECONNRESET',
]);

function describeCert(socket) {
  const peer = socket.getPeerCertificate(true);
  if (!peer || !peer.raw) return null;
  const x = new X509Certificate(peer.raw);
  const details = x.publicKey.asymmetricKeyDetails || {};
  return {
    subject: x.subject.replace(/\n/g, ', '),
    issuer: x.issuer.replace(/\n/g, ', '),
    validFrom: new Date(x.validFrom).toISOString(),
    validTo: new Date(x.validTo).toISOString(),
    altNames: x.subjectAltName || '',
    keyType: x.publicKey.asymmetricKeyType,
    keyBits: details.modulusLength || null,
    curve: details.namedCurve || null,
  };
}

export function probeTls({ host, address, port = 443, timeoutMs = 8000, minVersion, maxVersion, ciphers }) {
  return new Promise((resolve) => {
    let finished = false;
    const finish = (value, socket) => {
      if (finished) return;
      finished = true;
      socket?.destroy();
      resolve(value);
    };
    const socket = tls.connect({
      host: address,
      port,
      servername: /^[\d.]+$|:/.test(host) ? undefined : host,
      rejectUnauthorized: false,
      minVersion,
      maxVersion,
      ciphers,
      localAddress: config.egressIp || undefined,
    });
    socket.setTimeout(timeoutMs, () => finish({ ok: false, error: 'ETIMEDOUT' }, socket));
    socket.once('error', (err) => finish({ ok: false, error: err.code || err.message }, socket));
    socket.once('secureConnect', () => {
      let cert = null;
      try {
        cert = describeCert(socket);
      } catch {
        /* leave cert null */
      }
      finish(
        {
          ok: true,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher() || null,
          authorized: Boolean(socket.authorized),
          authError: socket.authorizationError ? String(socket.authorizationError) : null,
          cert,
        },
        socket,
      );
    });
  });
}

async function acceptsLegacy(opts, version) {
  const r = await probeTls({
    ...opts,
    minVersion: version,
    maxVersion: version,
    ciphers: 'ALL:@SECLEVEL=0',
  });
  if (r.ok) return true;
  return REFUSED.has(r.error) ? false : null; // null: could not tell
}

/** Handshake with the host, then check whether TLS 1.0 and 1.1 are still accepted. */
export async function inspectTls(opts) {
  const main = await probeTls(opts);
  if (!main.ok) return main;
  const [tls10, tls11] = await Promise.all([acceptsLegacy(opts, 'TLSv1'), acceptsLegacy(opts, 'TLSv1.1')]);
  return { ...main, legacy: { tls10, tls11 } };
}
