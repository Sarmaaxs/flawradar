import { extractResources } from './html.js';

// Sent as the Origin header on the CORS probe. The .invalid TLD never resolves.
export const PROBE_ORIGIN = 'https://flawradar-probe.invalid';

const MDN = 'https://developer.mozilla.org/en-US/docs/Web/';
const DEEP_SKIP = 'Deep scan not run. It needs proof that you control this host (see Verify).';

const ok = (detail, more = {}) => ({ status: 'pass', detail, ...more });
const bad = (detail, more = {}) => ({ status: 'fail', detail, ...more });
const warn = (detail, more = {}) => ({ status: 'warn', detail, ...more });
const info = (detail, more = {}) => ({ status: 'info', detail, ...more });
const skip = (detail, more = {}) => ({ status: 'skip', detail, ...more });

const headerFix = (name, value, text) => ({
  text,
  bundle: ['nginx', 'apache', 'express'],
  snippets: {
    nginx: `add_header ${name} "${value}" always;`,
    apache: `Header always set ${name} "${value}"`,
    express: `res.setHeader(${JSON.stringify(name)}, ${JSON.stringify(value)});`,
  },
});

const header = (ctx, name) => ctx.page?.res?.headers?.[name];

/** Header present on home, or only on a crawled subpage (path-specific config). */
function headerAnywhere(ctx, name) {
  const home = header(ctx, name);
  if (home) return { value: home, where: 'home' };
  for (const p of ctx.extraPages || []) {
    const v = p.res?.headers?.[name];
    if (v) return { value: v, where: p.path };
  }
  return null;
}


export function parseCsp(value) {
  const out = {};
  for (const part of String(value).split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens.shift().toLowerCase();
    if (!(name in out)) out[name] = tokens;
  }
  return out;
}

function parseCookies(list = []) {
  return list.map((raw) => {
    const parts = raw.split(';').map((s) => s.trim());
    const name = parts[0].split('=')[0].trim();
    const attrs = parts.slice(1);
    const has = (n) => attrs.some((a) => a.toLowerCase().split('=')[0] === n);
    const sameSite = (attrs.find((a) => /^samesite=/i.test(a)) || '').split('=')[1]?.toLowerCase() || null;
    return {
      name,
      secure: has('secure'),
      httpOnly: has('httponly'),
      sameSite,
      session: /(sess|sid|auth|token|jwt|login)/i.test(name) && !/(csrf|xsrf)/i.test(name),
    };
  });
}

const names = (cookies) => cookies.slice(0, 6).map((c) => c.name).join(', ') + (cookies.length > 6 ? ', ...' : '');

const TLS_ERRORS = {
  CERT_HAS_EXPIRED: 'The certificate has expired.',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'The certificate is self-signed, so browsers will not trust it.',
  SELF_SIGNED_CERT_IN_CHAIN: 'The certificate chain contains a self-signed certificate that is not a trusted root.',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    'The server did not send its intermediate certificate, so the chain cannot be verified.',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'The issuer of the certificate is not trusted, or was not sent by the server.',
  ERR_TLS_CERT_ALTNAME_INVALID: 'The certificate is not valid for this host name.',
  CERT_NOT_YET_VALID: 'The certificate is not valid yet. Check the server clock.',
};

export const CHECKS = [
  // ---------------------------------------------------------------- Transport
  {
    id: 'https',
    category: 'Transport',
    title: 'HTTPS is available',
    severity: 'critical',
    why: 'Without HTTPS, everything between the visitor and the server, including logins and cookies, can be read or changed by anyone on the network path.',
    ref: `${MDN}Security/Transport_Layer_Security`,
    run(ctx) {
      if (ctx.page.https) return ok(`The site answers over HTTPS (status ${ctx.page.res.status}).`);
      const why = ctx.page.httpsError ? ` (${ctx.page.httpsError})` : '';
      return bad(`The site did not answer over HTTPS${why}. It is only reachable over plain HTTP.`, {
        fix: {
          text: "Install a TLS certificate and serve the site on port 443. Certbot with Let's Encrypt is free and renews itself.",
        },
      });
    },
  },
  {
    id: 'http-redirect',
    category: 'Transport',
    title: 'HTTP redirects to HTTPS',
    severity: 'high',
    why: 'People still type http:// or follow old links. If port 80 serves the site, those visits are unprotected, and an attacker can strip HTTPS from the first request.',
    ref: `${MDN}HTTP/Redirections`,
    run(ctx) {
      if (!ctx.page.https) return skip('The site has no HTTPS to redirect to.');
      const r = ctx.http;
      if (!r) return skip('The HTTP redirect test did not run.');
      if (!r.res) {
        return info(`Nothing answered on port 80 (${r.error}). Visitors who type the bare address may not reach the site.`);
      }
      const { status, headers } = r.res;
      if ([301, 302, 303, 307, 308].includes(status) && headers.location) {
        let target;
        try {
          target = new URL(headers.location, `http://${ctx.host}/`);
        } catch {
          target = null;
        }
        if (target?.protocol === 'https:') {
          const note = [302, 303, 307].includes(status)
            ? ` It is a temporary redirect (${status}); 301 or 308 lets browsers remember it.`
            : '';
          return ok(`http:// redirects to ${target.origin} with status ${status}.${note}`);
        }
      }
      return bad(
        `Port 80 answers with status ${status} and does not send visitors to HTTPS.`,
        {
          fix: {
            text: 'Answer on port 80 with one permanent redirect to the HTTPS address and nothing else.',
            snippets: {
              nginx: `server {\n  listen 80;\n  server_name ${ctx.host};\n  return 301 https://$host$request_uri;\n}`,
              apache: `<VirtualHost *:80>\n  ServerName ${ctx.host}\n  Redirect permanent / https://${ctx.host}/\n</VirtualHost>`,
              express:
                "// Behind a proxy, call app.set('trust proxy', 1) first.\napp.use((req, res, next) =>\n  req.secure ? next() : res.redirect(301, `https://${req.headers.host}${req.originalUrl}`));",
            },
          },
        },
      );
    },
  },
  {
    id: 'tls-cert',
    category: 'Transport',
    title: 'TLS certificate is valid and trusted',
    severity: 'critical',
    why: 'An expired, self-signed or mismatched certificate makes browsers show a full-page warning and teaches visitors to click through warnings.',
    ref: `${MDN}Security/Transport_Layer_Security`,
    run(ctx) {
      const t = ctx.tls;
      if (!t) return skip('There was no HTTPS connection to inspect.');
      if (!t.ok) return bad(`The TLS handshake failed (${t.error}).`);
      const c = t.cert;
      if (!c) return warn('The server completed the handshake but sent no readable certificate.');
      const days = Math.floor((new Date(c.validTo).getTime() - Date.now()) / 86_400_000);
      const evidence = `Subject: ${c.subject}\nIssuer: ${c.issuer}\nValid until: ${c.validTo.slice(0, 10)} (${days} days)`;
      if (!t.authorized) {
        const message = TLS_ERRORS[t.authError] || `The certificate could not be verified (${t.authError}).`;
        return bad(message, {
          evidence,
          fix: {
            text: 'Install a certificate from a public CA that covers this host name and send the full chain. Certbot handles this for most servers.',
          },
        });
      }
      if (days < 14) return bad(`The certificate expires in ${days} days.`, { evidence, fix: renewFix() });
      if (days < 30) return warn(`The certificate expires in ${days} days.`, { evidence, fix: renewFix() });
      return ok(`The certificate is trusted and valid for ${days} more days.`, { evidence });
    },
  },
  {
    id: 'tls-key',
    category: 'Transport',
    title: 'Certificate key is strong enough',
    severity: 'medium',
    why: 'RSA keys under 2048 bits can be factored with modest resources. Elliptic curve keys are fine at standard sizes.',
    ref: `${MDN}Security/Transport_Layer_Security`,
    run(ctx) {
      const c = ctx.tls?.cert;
      if (!c) return skip('There was no certificate to inspect.');
      if (c.keyType === 'rsa') {
        if (c.keyBits && c.keyBits < 2048) {
          return bad(`The certificate uses a ${c.keyBits}-bit RSA key.`, {
            fix: { text: 'Issue a new certificate with an RSA key of at least 2048 bits, or an ECDSA P-256 key.' },
          });
        }
        return ok(`RSA ${c.keyBits}-bit key.`);
      }
      return ok(`${c.keyType.toUpperCase()} key${c.curve ? ` on curve ${c.curve}` : ''}.`);
    },
  },
  {
    id: 'tls-protocol',
    category: 'Transport',
    title: 'Old TLS versions are refused',
    severity: 'high',
    why: 'TLS 1.0 and 1.1 are deprecated and have known weaknesses. Every current browser speaks TLS 1.2 or 1.3.',
    ref: `${MDN}Security/Transport_Layer_Security`,
    run(ctx) {
      const t = ctx.tls;
      if (!t?.ok) return skip('There was no HTTPS connection to inspect.');
      const fix = {
        text: 'Allow only TLS 1.2 and 1.3.',
        bundle: ['nginx', 'apache'],
        snippets: {
          nginx: 'ssl_protocols TLSv1.2 TLSv1.3;',
          apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3',
        },
      };
      const accepted = [];
      if (t.legacy?.tls10) accepted.push('TLS 1.0');
      if (t.legacy?.tls11) accepted.push('TLS 1.1');
      if (accepted.length) {
        return bad(`The server still accepts ${accepted.join(' and ')}.`, {
          evidence: `Negotiated by default: ${t.protocol}`,
          fix,
        });
      }
      if (['SSLv3', 'TLSv1', 'TLSv1.1'].includes(t.protocol)) {
        return bad(`The server negotiated ${t.protocol}.`, { fix });
      }
      const cipher = t.cipher?.name ? ` with ${t.cipher.name}` : '';
      const unknown = t.legacy?.tls10 === null || t.legacy?.tls11 === null;
      if (unknown) {
        return ok(`Negotiated ${t.protocol}${cipher}. Old versions could not be probed from this scanner, so only the negotiated version was checked.`);
      }
      return ok(`Negotiated ${t.protocol}${cipher}. TLS 1.0 and 1.1 are refused.`);
    },
  },

  // ------------------------------------------------------------------ Headers
  {
    id: 'hsts',
    category: 'Headers',
    title: 'Strict-Transport-Security (HSTS)',
    severity: 'high',
    why: 'HSTS tells the browser to use HTTPS for this site and refuse to downgrade, which closes the gap left by the first plain HTTP request.',
    ref: `${MDN}HTTP/Headers/Strict-Transport-Security`,
    run(ctx) {
      if (!ctx.page.https) return skip('The page was not served over HTTPS, so HSTS does not apply.');
      const found = headerAnywhere(ctx, 'strict-transport-security');
      const v = found?.value;
      const fix = headerFix(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains',
        'Send the header on every HTTPS response. Add "preload" only after reading hstspreload.org, because it is hard to undo.',
      );
      if (!v) return bad('No Strict-Transport-Security header.', { fix });
      if (found.where !== 'home') {
        return warn(`HSTS is set on ${found.where} but not on the home page. Send it on every HTTPS response.`, {
          evidence: v,
          fix,
        });
      }
      const m = /max-age\s*=\s*"?(\d+)/i.exec(v);
      if (!m) return bad('The header is present but has no valid max-age.', { evidence: v, fix });
      const age = Number(m[1]);
      if (age === 0) return bad('max-age=0 switches HSTS off.', { evidence: v, fix });
      if (age < 15_552_000) {
        return warn(`max-age is ${Math.round(age / 86_400)} days. Use at least 180 days; one year is common.`, {
          evidence: v,
          fix,
        });
      }
      const sub = /includeSubDomains/i.test(v) ? '' : ' includeSubDomains is not set.';
      return ok(`max-age is ${Math.round(age / 86_400)} days.${sub}`, { evidence: v });
    },
  },
  {
    id: 'csp',
    category: 'Headers',
    title: 'Content-Security-Policy',
    severity: 'high',
    why: 'A CSP limits where scripts, frames and other resources may load from. It is the strongest browser-side defence against injected scripts (XSS).',
    ref: `${MDN}HTTP/Guides/CSP`,
    run(ctx) {
      const enforced = header(ctx, 'content-security-policy');
      const reportOnly = header(ctx, 'content-security-policy-report-only');
      const fix = headerFix(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'",
        'This starter policy allows only your own origin. Try it as Content-Security-Policy-Report-Only first and watch the reports; pages with inline scripts or third-party scripts will need adjustments.',
      );
      if (!enforced) {
        if (reportOnly) {
          return warn('Only Content-Security-Policy-Report-Only is set. It reports violations but blocks nothing.', {
            evidence: reportOnly,
            fix,
          });
        }
        return bad('No Content-Security-Policy header.', { fix });
      }
      const d = parseCsp(enforced);
      const script = d['script-src'] || d['default-src'] || [];
      const lower = script.map((s) => s.toLowerCase());
      const hasNonceOrHash = lower.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
      const problems = [];
      if (!d['script-src'] && !d['default-src']) problems.push('neither script-src nor default-src is set, so scripts are not restricted');
      if (lower.includes("'unsafe-inline'") && !hasNonceOrHash) problems.push("script-src allows 'unsafe-inline'");
      if (lower.includes("'unsafe-eval'")) problems.push("script-src allows 'unsafe-eval'");
      if (lower.includes('*') || lower.some((s) => /^(https?|data):$/.test(s))) {
        problems.push('script-src allows scripts from any host or a whole scheme');
      }
      if (!d['object-src'] && !d['default-src']) problems.push("object-src is not set (use 'none')");
      const notes = [];
      if (!d['base-uri']) notes.push('base-uri is not set.');
      if (!d['frame-ancestors']) notes.push('frame-ancestors is not set.');
      if (problems.length) {
        return warn(`A policy is set, but ${problems.join('; ')}.`, { evidence: enforced, fix });
      }
      return ok(`A policy is set and restricts scripts.${notes.length ? ` ${notes.join(' ')}` : ''}`, { evidence: enforced });
    },
  },
  {
    id: 'xcto',
    category: 'Headers',
    title: 'X-Content-Type-Options',
    severity: 'medium',
    why: 'Without nosniff, browsers may guess a file type and run an uploaded file as a script.',
    ref: `${MDN}HTTP/Headers/X-Content-Type-Options`,
    run(ctx) {
      const found = headerAnywhere(ctx, 'x-content-type-options');
      const v = found?.value;
      if (v && v.toLowerCase().includes('nosniff')) {
        if (found.where !== 'home') {
          return warn(`nosniff is set on ${found.where} but not on the home page.`, {
            fix: headerFix('X-Content-Type-Options', 'nosniff', 'Send the header on every response.'),
          });
        }
        return ok('nosniff is set.');
      }
      return bad('X-Content-Type-Options: nosniff is not set.', {
        fix: headerFix('X-Content-Type-Options', 'nosniff', 'Send the header on every response.'),
      });
    },
  },
  {
    id: 'framing',
    category: 'Headers',
    title: 'Clickjacking protection',
    severity: 'medium',
    why: 'If other sites can put yours in a frame, they can trick visitors into clicking buttons they cannot see.',
    ref: `${MDN}HTTP/Headers/X-Frame-Options`,
    run(ctx) {
      const xfoHome = header(ctx, 'x-frame-options');
      const cspHome = header(ctx, 'content-security-policy');
      const xfoFound = headerAnywhere(ctx, 'x-frame-options');
      const cspFound = headerAnywhere(ctx, 'content-security-policy');
      const xfo = xfoHome || xfoFound?.value;
      const csp = cspHome || cspFound?.value;
      const fa = csp ? parseCsp(csp)['frame-ancestors'] : null;
      if (fa) {
        if (!cspHome && cspFound) {
          return warn(`CSP frame-ancestors is set on ${cspFound.where} but not on the home page.`, {
            evidence: csp,
          });
        }
        return ok(`CSP frame-ancestors is ${fa.join(' ')}.`);
      }
      if (xfo && /^(deny|sameorigin)$/i.test(xfo.trim())) {
        if (!xfoHome && xfoFound) {
          return warn(`X-Frame-Options is set on ${xfoFound.where} but not on the home page.`, { evidence: xfo });
        }
        return ok(`X-Frame-Options is ${xfo}.`);
      }
      const fix = headerFix(
        'X-Frame-Options',
        'SAMEORIGIN',
        "Use X-Frame-Options: SAMEORIGIN, or the more flexible frame-ancestors directive in your Content-Security-Policy. Use DENY if nothing should frame the site.",
      );
      if (xfo) return warn(`X-Frame-Options is "${xfo}", which browsers do not honour.`, { fix });
      return bad('Neither X-Frame-Options nor CSP frame-ancestors is set.', { fix });
    },
  },
  {
    id: 'referrer',
    category: 'Headers',
    title: 'Referrer-Policy',
    severity: 'low',
    why: 'Without a policy, full page addresses, including tokens in query strings, can leak to other sites through the Referer header.',
    ref: `${MDN}HTTP/Headers/Referrer-Policy`,
    run(ctx) {
      const v = header(ctx, 'referrer-policy');
      const fix = headerFix('Referrer-Policy', 'strict-origin-when-cross-origin', 'Send the header on every response.');
      if (!v) return warn('Referrer-Policy is not set. Browsers apply their own default.', { fix });
      if (/(^|,\s*)(unsafe-url|no-referrer-when-downgrade)\s*$/i.test(v)) {
        return warn(`Referrer-Policy is "${v}", which sends full addresses to other sites.`, { evidence: v, fix });
      }
      return ok(`Referrer-Policy is ${v}.`);
    },
  },
  {
    id: 'permissions',
    category: 'Headers',
    title: 'Permissions-Policy',
    severity: 'low',
    why: 'Turns off browser features the site does not use, so injected or embedded code cannot ask for the camera, microphone or location.',
    ref: `${MDN}HTTP/Headers/Permissions-Policy`,
    run(ctx) {
      if (header(ctx, 'permissions-policy')) return ok('Permissions-Policy is set.');
      return warn('Permissions-Policy is not set.', {
        fix: headerFix(
          'Permissions-Policy',
          'camera=(), microphone=(), geolocation=()',
          'List the features you do not use. Remove any your site needs.',
        ),
      });
    },
  },
  {
    id: 'cors',
    category: 'Headers',
    title: 'CORS is not too open',
    severity: 'high',
    why: 'If the server echoes any Origin back and allows credentials, a hostile site can read a logged-in visitor\'s data from your API.',
    ref: `${MDN}HTTP/CORS`,
    run(ctx) {
      const r = ctx.cors?.res;
      if (!r) return skip('The CORS probe did not run.');
      const origin = r.headers['access-control-allow-origin'];
      const creds = String(r.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
      if (!origin) return ok('No CORS headers on the home page. Browsers block cross-origin reads.');
      const fix = {
        text: 'Compare the Origin header against a fixed list of allowed sites and echo it back only on a match. Never combine a reflected origin with Allow-Credentials.',
      };
      if (origin === PROBE_ORIGIN && creds) {
        return bad('The server reflects any Origin and allows credentials. Any website can read logged-in responses.', {
          evidence: `Origin sent: ${PROBE_ORIGIN}\nAccess-Control-Allow-Origin: ${origin}\nAccess-Control-Allow-Credentials: true`,
          fix,
        });
      }
      if (origin === PROBE_ORIGIN) {
        return warn('The server reflects any Origin in Access-Control-Allow-Origin. That is fine for public data and risky for anything tied to a session.', { fix });
      }
      if (origin === '*') return info('Access-Control-Allow-Origin is *. Any site can read this response. Fine for public data.');
      return ok(`Access-Control-Allow-Origin is limited to ${origin}.`);
    },
  },
  {
    id: 'banner',
    category: 'Headers',
    title: 'Software versions are not advertised',
    severity: 'low',
    why: 'Exact version numbers tell an attacker which known vulnerabilities to try. Hiding them is not a fix, but it removes free information.',
    ref: `${MDN}HTTP/Headers/Server`,
    run(ctx) {
      const leaks = [];
      const server = header(ctx, 'server');
      if (server && /\d+(\.\d+)+/.test(server)) leaks.push(`Server: ${server}`);
      if (header(ctx, 'x-powered-by')) leaks.push(`X-Powered-By: ${header(ctx, 'x-powered-by')}`);
      if (header(ctx, 'x-aspnet-version')) leaks.push(`X-AspNet-Version: ${header(ctx, 'x-aspnet-version')}`);
      if (!leaks.length) return ok(server ? `The Server header is "${server}" with no version.` : 'No software or version headers.');
      return warn('Response headers reveal the software in use.', {
        evidence: leaks.join('\n'),
        fix: {
          text: 'Turn off version output. For PHP set expose_php = Off in php.ini.',
          bundle: ['nginx', 'express'],
          snippets: {
            nginx: 'server_tokens off;',
            apache: 'ServerTokens Prod\nServerSignature Off',
            express: "res.removeHeader('X-Powered-By');",
          },
        },
      });
    },
  },

  // ------------------------------------------------------------------ Cookies
  {
    id: 'cookie-secure',
    category: 'Cookies',
    title: 'Cookies have the Secure flag',
    severity: 'high',
    why: 'A cookie without Secure is also sent over plain HTTP, where it can be read from the network.',
    ref: `${MDN}HTTP/Headers/Set-Cookie`,
    run(ctx) {
      const cookies = parseCookies(ctx.page.res.headers['set-cookie']);
      if (!cookies.length) return info('The home page sets no cookies.');
      if (!ctx.page.https) return skip('The page was not served over HTTPS.');
      const missing = cookies.filter((c) => !c.secure);
      if (!missing.length) return ok(`All ${cookies.length} cookies are Secure.`);
      const sessionLike = missing.some((c) => c.session);
      const make = sessionLike ? bad : warn;
      return make(`Cookies without Secure: ${missing.length} of ${cookies.length}.`, {
        evidence: names(missing),
        fix: cookieFix(),
      });
    },
  },
  {
    id: 'cookie-httponly',
    category: 'Cookies',
    title: 'Cookies have the HttpOnly flag',
    severity: 'medium',
    why: 'HttpOnly keeps scripts from reading the cookie, so a cross-site scripting hole cannot steal the session.',
    ref: `${MDN}HTTP/Headers/Set-Cookie`,
    run(ctx) {
      const cookies = parseCookies(ctx.page.res.headers['set-cookie']);
      if (!cookies.length) return info('The home page sets no cookies.');
      const missing = cookies.filter((c) => !c.httpOnly);
      if (!missing.length) return ok(`All ${cookies.length} cookies are HttpOnly.`);
      const sessionLike = missing.some((c) => c.session);
      const make = sessionLike ? bad : warn;
      return make(`Cookies without HttpOnly: ${missing.length} of ${cookies.length}.`, {
        evidence: names(missing),
        fix: cookieFix(),
      });
    },
  },
  {
    id: 'cookie-samesite',
    category: 'Cookies',
    title: 'Cookies have a SameSite attribute',
    severity: 'low',
    why: 'SameSite stops the browser from attaching the cookie to requests started by other sites, which blocks most cross-site request forgery.',
    ref: `${MDN}HTTP/Headers/Set-Cookie`,
    run(ctx) {
      const cookies = parseCookies(ctx.page.res.headers['set-cookie']);
      if (!cookies.length) return info('The home page sets no cookies.');
      const noneInsecure = cookies.filter((c) => c.sameSite === 'none' && !c.secure);
      if (noneInsecure.length) {
        return bad('SameSite=None is used without Secure, which browsers reject.', {
          evidence: names(noneInsecure),
          fix: cookieFix(),
        });
      }
      const missing = cookies.filter((c) => !c.sameSite);
      if (!missing.length) return ok(`All ${cookies.length} cookies set SameSite.`);
      return warn(`Cookies without SameSite: ${missing.length} of ${cookies.length}.`, {
        evidence: names(missing),
        fix: cookieFix(),
      });
    },
  },

  // ------------------------------------------------------------------ Content
  {
    id: 'mixed-content',
    category: 'Content',
    title: 'No mixed content',
    severity: 'high',
    why: 'An HTTPS page that loads scripts or styles over HTTP lets anyone on the network rewrite those files and take over the page.',
    ref: `${MDN}Security/Mixed_content`,
    run(ctx) {
      if (!ctx.page.https) return skip('The page was not served over HTTPS.');
      if (!isHtml(ctx)) return skip('The home page is not HTML.');
      const r = extractResources(ctx.page.res.body, ctx.page.res.url);
      const insecure = (list) => list.map((x) => x.url).filter((u) => u.startsWith('http://'));
      const active = [...insecure(r.scripts), ...insecure(r.styles), ...insecure(r.frames)];
      const passive = insecure(r.media);
      const fix = { text: 'Change these addresses to https:// or to paths relative to the site. If the other host has no HTTPS, host the file yourself.' };
      if (active.length) {
        return bad(`${active.length} script, stylesheet or frame loads over HTTP.`, {
          evidence: [...active, ...passive].slice(0, 8).join('\n'),
          fix,
        });
      }
      if (passive.length) {
        return warn(`${passive.length} image or media file loads over HTTP.`, { evidence: passive.slice(0, 8).join('\n'), fix });
      }
      return ok('No HTTP resources found on the home page.');
    },
  },
  {
    id: 'sri',
    category: 'Content',
    title: 'Third-party scripts use Subresource Integrity',
    severity: 'low',
    why: 'If a third-party host is compromised, every site that loads its script is compromised too. An integrity hash makes the browser refuse a changed file.',
    ref: `${MDN}Security/Subresource_Integrity`,
    run(ctx) {
      if (!isHtml(ctx)) return skip('The home page is not HTML.');
      const base = new URL(ctx.page.res.url);
      const r = extractResources(ctx.page.res.body, base.href);
      const external = [...r.scripts, ...r.styles].filter((x) => new URL(x.url).origin !== base.origin);
      if (!external.length) return ok('No third-party scripts or stylesheets on the home page.');
      const bare = external.filter((x) => !x.integrity);
      if (!bare.length) return ok(`All ${external.length} third-party files have an integrity hash.`);
      return warn(`Third-party files without an integrity attribute: ${bare.length} of ${external.length}.`, {
        evidence: bare.slice(0, 6).map((x) => x.url).join('\n'),
        fix: {
          text: 'Add integrity="sha384-..." and crossorigin="anonymous" to the tag. Generate the hash with: openssl dgst -sha384 -binary file.js | openssl base64 -A. Skip this for files the vendor changes in place, such as analytics loaders.',
        },
      });
    },
  },
  {
    id: 'password-form',
    category: 'Content',
    title: 'Password forms are submitted over HTTPS',
    severity: 'critical',
    why: 'A login form on a plain HTTP page, or one that posts to HTTP, sends passwords where anyone on the network can read them.',
    ref: `${MDN}Security/Practical_implementation_guides/TLS`,
    run(ctx) {
      if (!isHtml(ctx)) return skip('The home page is not HTML.');
      const forms = extractResources(ctx.page.res.body, ctx.page.res.url).forms.filter((f) => f.hasPassword);
      if (!forms.length) return info('No password field on the home page.');
      const unsafe = forms.filter((f) => !ctx.page.https || (f.action && f.action.startsWith('http://')));
      if (unsafe.length) {
        return bad('A password field is on a page or form that uses plain HTTP.', {
          evidence: unsafe.map((f) => f.action).join('\n'),
          fix: { text: 'Serve the page over HTTPS and set the form action to an https:// address.' },
        });
      }
      return ok('Password forms are served and submitted over HTTPS.');
    },
  },

  // -------------------------------------------------------------- DNS and mail
  {
    id: 'spf',
    category: 'DNS and mail',
    title: 'SPF record',
    severity: 'medium',
    why: 'SPF lists the servers allowed to send mail for the domain. Without it, anyone can send mail that claims to be from you and receivers cannot tell.',
    ref: 'https://www.rfc-editor.org/rfc/rfc7208',
    run(ctx) {
      const d = ctx.dns;
      if (!d || d.spf === null) return skip('The DNS lookup did not complete.');
      const sendsMail = d.mx === null ? true : d.mx.length > 0;
      const fix = {
        text: sendsMail
          ? 'Publish one TXT record at the domain listing your mail senders. Replace the include with your provider, then end with -all once you are sure the list is complete.'
          : 'This domain has no mail servers. A TXT record that allows nothing stops others from spoofing it.',
        snippets: { dns: sendsMail ? `${d.apex}.  TXT  "v=spf1 include:_spf.example.net ~all"` : `${d.apex}.  TXT  "v=spf1 -all"` },
      };
      if (d.spf.length === 0) {
        return sendsMail
          ? bad('No SPF record.', { fix })
          : info('No SPF record. The domain has no MX records, so only spoofing protection is missing.', { fix });
      }
      if (d.spf.length > 1) return bad('There is more than one SPF record. Receivers treat that as an error and ignore all of them.', { evidence: d.spf.join('\n') });
      const rec = d.spf[0];
      const all = /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(rec);
      if (!all) {
        if (/redirect=/i.test(rec)) return ok('SPF redirects to another domain.', { evidence: rec });
        return warn('The SPF record has no "all" mechanism, so it does not say what to do with other senders.', { evidence: rec, fix });
      }
      const q = all[1] || '+';
      if (q === '+') return bad('SPF ends in +all, which lets every server send as this domain.', { evidence: rec, fix });
      if (q === '?') return warn('SPF ends in ?all, which gives no protection.', { evidence: rec, fix });
      return ok(q === '-' ? 'SPF ends in -all (reject others).' : 'SPF ends in ~all (soft fail others).', { evidence: rec });
    },
  },
  {
    id: 'dmarc',
    category: 'DNS and mail',
    title: 'DMARC record',
    severity: 'medium',
    why: 'DMARC tells receivers what to do with mail that fails SPF and DKIM, and sends you reports. Without it, spoofed mail from your domain is usually delivered.',
    ref: 'https://www.rfc-editor.org/rfc/rfc7489',
    run(ctx) {
      const d = ctx.dns;
      if (!d || d.dmarc === null) return skip('The DNS lookup did not complete.');
      const sendsMail = d.mx === null ? true : d.mx.length > 0;
      const fix = {
        text: 'Start with p=none and a report address, read the reports for a few weeks, then move to quarantine and reject.',
        snippets: { dns: `_dmarc.${d.apex}.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@${d.apex}"` },
      };
      if (!d.dmarc.length) {
        return sendsMail ? bad('No DMARC record.', { fix }) : info('No DMARC record. The domain has no MX records.', { fix });
      }
      const rec = d.dmarc[0];
      const policy = (/(?:^|;)\s*p\s*=\s*(\w+)/i.exec(rec) || [])[1]?.toLowerCase();
      if (policy === 'none') return warn('DMARC policy is p=none. It monitors but does not block spoofed mail.', { evidence: rec, fix });
      if (policy === 'quarantine' || policy === 'reject') return ok(`DMARC policy is p=${policy}.`, { evidence: rec });
      return warn('The DMARC record has no valid p= policy.', { evidence: rec, fix });
    },
  },
  {
    id: 'caa',
    category: 'DNS and mail',
    title: 'CAA record',
    severity: 'low',
    why: 'A CAA record names the certificate authorities allowed to issue certificates for the domain, which narrows the damage from a mistaken or fraudulent issuance.',
    ref: 'https://www.rfc-editor.org/rfc/rfc8659',
    run(ctx) {
      const d = ctx.dns;
      if (!d || d.caa === null) return skip('The DNS lookup did not complete.');
      if (d.caa.length) return ok(`CAA allows: ${d.caa.filter(Boolean).join(', ') || 'see record'}.`);
      return warn('No CAA record. Any certificate authority may issue certificates for this domain.', {
        fix: { text: "Add a CAA record for the CA you use, for example Let's Encrypt.", snippets: { dns: `${d.apex}.  CAA  0 issue "letsencrypt.org"` } },
      });
    },
  },

  // --------------------------------------------------------------- Disclosure
  {
    id: 'security-txt',
    category: 'Disclosure',
    title: 'security.txt tells researchers where to report',
    severity: 'low',
    why: 'Without a published contact, people who find a hole in your site have no clear way to tell you, and some will give up or go public.',
    ref: 'https://www.rfc-editor.org/rfc/rfc9116',
    run(ctx) {
      const s = ctx.securityTxt;
      if (!s) return skip('The security.txt lookup did not run.');
      const fix = {
        text: 'Publish a plain text file at /.well-known/security.txt with a Contact line and an Expires date.',
        snippets: { file: 'Contact: mailto:security@your-domain.example\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en' },
      };
      if (!s.found) return warn('No security.txt at /.well-known/security.txt.', { fix });
      if (!s.expires) return warn('security.txt has no Expires field, which the standard requires.', { evidence: s.path, fix });
      if (new Date(s.expires).getTime() < Date.now()) return warn('security.txt has expired.', { evidence: `Expires: ${s.expires}`, fix });
      return ok('security.txt has a Contact and a current Expires date.', { evidence: s.path });
    },
  },

  // ----------------------------------------------------------------- Exposure
  ...[
    ['exposed-vcs', 'Version control files are not exposed', 'critical', 'vcs',
      'An exposed .git directory lets anyone download the full source code and its history, which often contains passwords and keys.'],
    ['exposed-env', 'Environment files are not exposed', 'critical', 'env',
      'A readable .env file usually holds database passwords and API keys.'],
    ['exposed-backup', 'Backups and configuration copies are not exposed', 'critical', 'backup',
      'Database dumps, site archives and copies of config files like wp-config.php.bak are served as plain downloads by most web servers.'],
    ['exposed-keys', 'Private keys and credential files are not exposed', 'critical', 'keys',
      'Private keys, .htpasswd, .npmrc and cloud credential files give direct access to servers, packages and accounts.'],
    ['exposed-admin', 'Admin panels, API docs and actuator endpoints are not public', 'high', 'admin',
      'Database panels, Spring actuator endpoints and API specifications on a public address hand attackers a map of the system, and sometimes the keys to it.'],
    ['exposed-misc', 'Debug and server status pages are not exposed', 'medium', 'misc',
      'phpinfo(), server-status and .DS_Store files reveal paths, versions and settings that help an attacker.'],
  ].map(([id, title, severity, group, why]) => ({
    id,
    category: 'Exposure',
    deep: true,
    title,
    severity,
    why,
    ref: 'https://owasp.org/www-project-web-security-testing-guide/',
    run(ctx) {
      if (!ctx.deep) return skip(DEEP_SKIP);
      const hits = ctx.deep.hits.filter((h) => h.group === group);
      if (!hits.length) return ok('Nothing found at the paths tested.');
      return bad(`${hits.length} sensitive ${hits.length === 1 ? 'path is' : 'paths are'} publicly readable.`, {
        evidence: hits.map((h) => `${h.path}  (HTTP ${h.status})`).join('\n'),
        fix: {
          text: 'Remove the file from the web root. If it held secrets, assume they were read and rotate them. Then block dotfiles at the server.',
          snippets: {
            nginx: 'location ~ /\\.(?!well-known) {\n  deny all;\n}',
            apache: '<FilesMatch "^\\.">\n  Require all denied\n</FilesMatch>',
          },
        },
      });
    },
  })),
  {
    id: 'dir-listing',
    category: 'Exposure',
    deep: true,
    title: 'Directory listings are off',
    severity: 'medium',
    why: 'Directory listings show every file in a folder, including ones you never linked to.',
    ref: 'https://owasp.org/www-project-web-security-testing-guide/',
    run(ctx) {
      if (!ctx.deep) return skip(DEEP_SKIP);
      if (!ctx.deep.listings.length) return ok('No directory listing found at the paths tested.');
      return bad('A directory listing is visible.', {
        evidence: ctx.deep.listings.join('\n'),
        fix: {
          text: 'Turn off automatic indexes.',
          snippets: { nginx: 'autoindex off;', apache: 'Options -Indexes' },
        },
      });
    },
  },
  {
    id: 'http-methods',
    category: 'Exposure',
    deep: true,
    title: 'Risky HTTP methods are not advertised',
    severity: 'medium',
    why: 'TRACE can leak headers, and PUT or DELETE on a public site usually means a misconfiguration.',
    ref: `${MDN}HTTP/Reference/Methods`,
    run(ctx) {
      if (!ctx.deep) return skip(DEEP_SKIP);
      const allow = ctx.deep.allow;
      if (!allow) return info('The server did not list allowed methods in response to OPTIONS.');
      const risky = allow.filter((m) => ['TRACE', 'PUT', 'DELETE', 'CONNECT'].includes(m));
      if (!risky.length) return ok(`Allowed methods: ${allow.join(', ')}.`);
      return bad(`The server advertises ${risky.join(', ')}.`, {
        evidence: `Allow: ${allow.join(', ')}`,
        fix: {
          text: 'Allow only the methods the site uses.',
          snippets: {
            nginx: 'if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) {\n  return 405;\n}',
            apache: 'TraceEnable off\n<LimitExcept GET POST HEAD OPTIONS>\n  Require all denied\n</LimitExcept>',
          },
        },
      });
    },
  },
];

function isHtml(ctx) {
  return /html/i.test(String(ctx.page.res.headers['content-type'] || '')) && Boolean(ctx.page.res.body);
}

function renewFix() {
  return { text: 'Renew the certificate now, then check that automatic renewal works. With Certbot: certbot renew --dry-run.' };
}

function cookieFix() {
  return {
    text: 'Set Secure, HttpOnly and SameSite when the cookie is created. The server snippets below add the flags to every cookie the app sends; skip HttpOnly for any cookie your own scripts must read.',
    snippets: {
      express: "res.cookie('name', value, { secure: true, httpOnly: true, sameSite: 'lax' });",
      nginx: 'proxy_cookie_flags ~ secure httponly samesite=lax;  # nginx 1.19.3 or newer, for proxied apps',
      apache: 'Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"  # adds flags even if already present',
    },
  };
}

export function evaluate(ctx) {
  return CHECKS.map((check) => {
    let result;
    try {
      result = check.run(ctx);
    } catch (err) {
      result = skip(`This check could not run: ${err.message}`);
    }
    return {
      id: check.id,
      category: check.category,
      title: check.title,
      severity: check.severity,
      ref: check.ref,
      ...result,
    };
  });
}

export function listChecks() {
  return CHECKS.map(({ id, category, title, severity, why, ref, deep }) => ({
    id,
    category,
    title,
    severity,
    why,
    ref,
    deep: Boolean(deep),
  }));
}
