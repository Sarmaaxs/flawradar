// "Check it yourself": for each finding, the plain terminal command that shows the same thing.
// Nothing here talks to the server. It only builds text from a finding and the host name.

const SAFE_HOST = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i;
const SAFE_PATH = /^\/[A-Za-z0-9._~\/%@+=:-]{0,120}$/;

const headerGrep = (host, name) => `curl -sSI https://${host}/ | grep -i '^${name}'`;

const HEADERS = {
  hsts: 'strict-transport-security',
  csp: 'content-security-policy',
  xcto: 'x-content-type-options',
  referrer: 'referrer-policy',
  permissions: 'permissions-policy',
};

/** Returns a shell command string, or null when there is nothing sensible to run. */
export function reproduce(finding, host) {
  if (!finding || typeof host !== 'string' || !SAFE_HOST.test(host)) return null;
  const id = finding.id;
  if (HEADERS[id]) return headerGrep(host, HEADERS[id]);
  switch (id) {
    case 'https': return `curl -sSI https://${host}/ | head -n 1`;
    case 'http-redirect': return `curl -sSI http://${host}/ | grep -i -E '^(HTTP|location)'`;
    case 'tls-cert':
    case 'tls-key':
      return `echo | openssl s_client -connect ${host}:443 -servername ${host} 2>/dev/null | openssl x509 -noout -subject -issuer -dates`;
    case 'tls-protocol':
      return `echo | openssl s_client -connect ${host}:443 -servername ${host} -tls1_1 2>&1 | grep -i -E 'protocol|alert|handshake'`;
    case 'framing': return `curl -sSI https://${host}/ | grep -i -E '^(x-frame-options|content-security-policy)'`;
    case 'cors': return `curl -sSI https://${host}/ -H 'Origin: https://flawradar-probe.invalid' | grep -i '^access-control'`;
    case 'banner':
    case 'old-software':
      return `curl -sSI https://${host}/ | grep -i -E '^(server|x-powered-by|x-aspnet-version)'`;
    case 'cookie-secure':
    case 'cookie-httponly':
    case 'cookie-samesite':
      return `curl -sSI https://${host}/ | grep -i '^set-cookie'`;
    case 'mixed-content': return `curl -sS https://${host}/ | grep -n -i -E "(src|href)=[\\"']http://"`;
    case 'sri': return `curl -sS https://${host}/ | grep -n -i -E '<script[^>]+src='`;
    case 'password-form': return `curl -sS https://${host}/ | grep -n -i 'type=.password'`;
    case 'spf': return `dig +short TXT ${host} | grep -i 'v=spf1'`;
    case 'dmarc': return `dig +short TXT _dmarc.${host}`;
    case 'caa': return `dig +short CAA ${host}`;
    case 'security-txt': return `curl -sS https://${host}/.well-known/security.txt`;
    case 'dir-listing': return `curl -sS https://${host}/uploads/ | head -n 20`;
    case 'http-methods': return `curl -sSI -X OPTIONS https://${host}/ | grep -i '^allow'`;
    default:
      break;
  }
  if (id.startsWith('exposed-')) {
    const paths = String(finding.evidence || '').split('\n').map((l) => l.trim().split(/\s+/)[0]).filter((p) => SAFE_PATH.test(p)).slice(0, 5);
    if (!paths.length) return null;
    return paths.map((p) => `curl -sS -o /dev/null -w '%{http_code}  ${p}\\n' https://${host}${p}`).join('\n');
  }
  return null;
}
