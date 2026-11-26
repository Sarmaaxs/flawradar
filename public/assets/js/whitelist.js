import { api, h } from './dom.js';

const $ = (selector) => document.querySelector(selector);
const isV4 = (ip) => !ip.includes(':');

async function main() {
  const info = await api('/api/scanner');
  const holder = $('#ips');
  if (!info.ips.length) {
    holder.replaceChildren(h('p', { class: 'alert warn' }, 'Scanner addresses are not published. Check back later.'));
  } else {
    const rows = info.ips.map((ip) => h('tr', {},
      h('td', { class: 'mono' }, ip),
      h('td', {}, isV4(ip) ? 'IPv4' : 'IPv6'),
    ));
    holder.replaceChildren(
      h('table', { 'aria-label': 'Scanner addresses' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Address'), h('th', {}, 'Family'))),
        h('tbody', {}, ...rows),
      ),
      h('p', {}, h('small', {}, 'Only allow-list addresses you have independently verified.')),
    );
  }
  if (info.contact) {
    const box = $('#contact');
    box.replaceChildren('Contact: ', h('b', {}, info.contact));
    box.hidden = false;
  }
}

main().catch((err) => {
  $('#ips').replaceChildren(h('p', { class: 'alert' }, `Could not load the address list (${err.message}).`));
});
