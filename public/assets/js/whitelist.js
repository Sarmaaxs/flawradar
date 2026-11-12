import { codeTabs } from './components.js';
import { api, h } from './dom.js';

const $ = (sel) => document.querySelector(sel);

const v4 = (ip) => !ip.includes(':');

function rules(ips, ua) {
  const quote = (s) => s.replace(/(["\\$])/g, '\\$1');
  const nginxAllow = ips.map((ip) => `    allow ${ip};`).join('\n');
  const nginx = [
    '# Skip rate limiting for Wsec. "geo" belongs in the http { } block.',
    'geo $wsec_scanner {',
    '    default 0;',
    ...ips.map((ip) => `    ${ip} 1;`),
    '}',
    '',
    'map $wsec_scanner $wsec_limit_key {',
    '    1 "";                       # an empty key is not counted',
    '    default $binary_remote_addr;',
    '}',
    '',
    'limit_req_zone $wsec_limit_key zone=perip:10m rate=10r/s;',
    '',
    '# To restrict a path to these addresses only, inside a location block:',
    '# location /internal/ {',
    nginxAllow.replace(/^/gm, '# '),
    '#     deny all;',
    '# }',
  ].join('\n');

  const modsec = [
    '# ModSecurity 2 or 3. Put before the CRS rules are included.',
    `SecRule REMOTE_ADDR "@ipMatch ${ips.join(',')}" \\`,
    '    "id:1000100,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"',
    '',
    '# Narrower: keep the engine on, but skip the scanner-detection rules only.',
    `# SecRule REMOTE_ADDR "@ipMatch ${ips.join(',')}" \\`,
    '#     "id:1000101,phase:1,pass,nolog,ctl:ruleRemoveById=913100-913110"',
  ].join('\n');

  const fail2ban = [
    '# /etc/fail2ban/jail.local',
    '[DEFAULT]',
    `ignoreip = 127.0.0.1/8 ::1 ${ips.join(' ')}`,
    '',
    '# Then: fail2ban-client reload',
  ].join('\n');

  const ufw = [
    '# Only needed if you restrict ports 80 and 443 by source address.',
    ...ips.flatMap((ip) => [`ufw allow from ${ip} to any port 80 proto tcp`, `ufw allow from ${ip} to any port 443 proto tcp`]),
  ].join('\n');

  const cloudflare = [
    'Security > WAF > Tools > IP Access Rules',
    ...ips.map((ip) => `  Add: ${ip}   Action: Allow   Zone: this website`),
    '',
    'Custom rule instead (Security > WAF > Custom rules), action "Skip":',
    `  (ip.src in {${ips.join(' ')}})`,
    '  Skip: all managed rules, rate limiting rules, Bot Fight Mode / Super Bot Fight Mode',
    '',
    `Optional second condition: and http.user_agent contains "Wsec-Scanner"`,
    '',
    'Bot Fight Mode on the free plan cannot be skipped by a custom rule.',
    'If scans are still blocked, turn it off for the test or use IP Access Rules above.',
  ].join('\n');

  return { nginx, modsec, fail2ban, ufw, cloudflare, ua: quote(ua) };
}

async function main() {
  const info = await api('/api/scanner');
  // w-copy renders once when connected, so build a fresh one with the text in place.
  const ua = document.createElement('w-copy');
  ua.setAttribute('label', 'User-Agent header');
  ua.textContent = info.userAgent;
  $('#ua').replaceWith(ua);

  const holder = $('#ips');
  const rulesHolder = $('#rules');

  if (!info.ips.length) {
    holder.replaceChildren(
      h(
        'p',
        { class: 'alert warn' },
        'This Wsec instance has no published scanner addresses. The person who runs it needs to set ',
        h('code', {}, 'WSEC_PUBLIC_IPS'),
        ' to the address or addresses its outgoing requests leave from. Until then there is nothing to allow-list.',
      ),
    );
    rulesHolder.replaceChildren(h('p', { class: 'muted' }, 'Rules appear here once addresses are published.'));
  } else {
    const rows = info.ips.map((ip) => h('tr', {}, h('td', { class: 'mono' }, ip), h('td', {}, v4(ip) ? 'IPv4' : 'IPv6')));
    holder.replaceChildren(
      h('table', { 'aria-label': 'Scanner addresses' }, h('thead', {}, h('tr', {}, h('th', {}, 'Address'), h('th', {}, 'Family'))), h('tbody', {}, ...rows)),
      h('p', {}, h('small', {}, 'Allow every address on the list. The list can change, so check this page when you review your firewall.')),
    );

    const r = rules(info.ips, info.userAgent);
    rulesHolder.replaceChildren(
      codeTabs(
        { nginx: r.nginx, modsec: r.modsec, fail2ban: r.fail2ban, ufw: r.ufw, cloudflare: r.cloudflare },
        { nginx: 'nginx', modsec: 'ModSecurity', fail2ban: 'fail2ban', ufw: 'ufw', cloudflare: 'Cloudflare' },
      ),
    );
  }

  if (info.contact) {
    const box = $('#contact');
    box.replaceChildren('Questions or abuse reports about scans from this service: ', h('b', {}, info.contact));
    box.hidden = false;
  }
}

main().catch((err) => {
  $('#ips').replaceChildren(h('p', { class: 'alert' }, `Could not load the scanner details (${err.message}).`));
});
