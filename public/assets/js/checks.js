import './components.js';
import { api, h, safeHttpsUrl } from './dom.js';

const order = ['Transport', 'Headers', 'Cookies', 'Content', 'DNS and mail', 'Disclosure', 'Exposure'];

try {
  const { checks } = await api('/api/checks');
  const groups = new Map();
  for (const c of checks) {
    if (!groups.has(c.category)) groups.set(c.category, []);
    groups.get(c.category).push(c);
  }
  const nodes = [];
  for (const category of [...groups.keys()].sort((a, b) => order.indexOf(a) - order.indexOf(b))) {
    nodes.push(h('h2', {}, category));
    for (const c of groups.get(category)) {
      const ref = safeHttpsUrl(c.ref);
      nodes.push(
        h(
          'div',
          {},
          h('h3', {}, c.title, ' ', h('small', {}, `(${c.severity}${c.deep ? ', deep scan only' : ''})`)),
          h('p', {}, c.why, ref ? [' ', h('a', { href: ref, rel: 'noopener noreferrer', target: '_blank' }, 'Reference')] : null),
        ),
      );
    }
  }
  document.getElementById('list').replaceChildren(...nodes);
} catch (err) {
  document.getElementById('list').replaceChildren(h('p', { class: 'alert' }, `Could not load the list (${err.message}).`));
}
