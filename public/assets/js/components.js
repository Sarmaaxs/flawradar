// Small set of custom elements used across the pages.
// All of them render into the page itself (no shadow DOM) so the stylesheet applies.

import { h } from './dom.js';

const NAV = [
  ['scan', '/', 'Scan'],
  ['whitelist', '/whitelist', 'Whitelist'],
  ['verify', '/verify', 'Verify'],
  ['checks', '/checks', 'Checks'],
  ['about', '/about', 'About'],
];

/** <w-header current="scan"> */
class WHeader extends HTMLElement {
  connectedCallback() {
    if (this.dataset.ready) return;
    this.dataset.ready = '1';
    const current = this.getAttribute('current');
    const nav = h('nav', { 'aria-label': 'Main' }, '[ ');
    NAV.forEach(([key, href, label], i) => {
      if (i) nav.append(' | ');
      nav.append(key === current ? h('b', { 'aria-current': 'page' }, label) : h('a', { href }, label));
    });
    nav.append(' ]');
    this.replaceChildren(
      h('header', { class: 'site-head' }, h('div', { class: 'brand' }, h('a', { href: '/' }, 'Wsec'), h('span', {}, 'web security checker')), nav),
    );
  }
}

/** <w-footer> */
class WFooter extends HTMLElement {
  connectedCallback() {
    if (this.dataset.ready) return;
    this.dataset.ready = '1';
    this.replaceChildren(
      h(
        'footer',
        { class: 'site-foot' },
        h('p', {}, 'Wsec makes read-only requests from the addresses on the ', h('a', { href: '/whitelist' }, 'whitelist'), ' page. ', h('a', { href: '/about' }, 'What it sends and what it keeps.')),
      ),
    );
  }
}

/** <w-status value="fail"> prints [FAIL] */
class WStatus extends HTMLElement {
  static observedAttributes = ['value'];
  connectedCallback() { this.render(); }
  attributeChangedCallback() { this.render(); }
  render() {
    const v = this.getAttribute('value') || '';
    this.textContent = `[${v.toUpperCase()}]`;
    this.setAttribute('role', 'text');
  }
}

/** <w-score score="72" grade="C"> */
class WScore extends HTMLElement {
  static observedAttributes = ['score', 'grade'];
  connectedCallback() { this.render(); }
  attributeChangedCallback() { if (this.isConnected) this.render(); }
  render() {
    const score = Math.max(0, Math.min(100, Number(this.getAttribute('score')) || 0));
    const fill = h('i');
    fill.style.width = `${score}%`;
    this.replaceChildren(
      h(
        'div',
        { class: 'scorebox' },
        h('span', { class: 'grade' }, this.getAttribute('grade') || '?'),
        h('span', { class: 'points' }, `${score} out of 100`),
        h('div', { class: 'bar', role: 'img', 'aria-label': `Score ${score} out of 100` }, fill),
      ),
    );
  }
}

/** <w-copy label="nginx">text to copy</w-copy> */
class WCopy extends HTMLElement {
  connectedCallback() {
    if (this._built) return;
    this._built = true;
    const code = this.textContent.replace(/^\n+|\n+$/g, '');
    const button = h('button', { type: 'button', class: 'small' }, 'Copy');
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(code);
      } catch {
        const range = document.createRange();
        range.selectNodeContents(pre);
        const sel = getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('copy');
        sel.removeAllRanges();
      }
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = 'Copy'; }, 1500);
    });
    const pre = h('pre', {}, code);
    const label = this.getAttribute('label');
    this.replaceChildren(h('div', { class: 'copy-bar' }, h('span', {}, label || ''), button), pre);
  }
}

/** <w-tabs><section data-tab="nginx">...</section>...</w-tabs> */
class WTabs extends HTMLElement {
  connectedCallback() {
    if (this._built) return;
    this._built = true;
    const panels = [...this.querySelectorAll(':scope > section[data-tab]')];
    if (!panels.length) return;
    const bar = h('div', { class: 'tabs', role: 'tablist' });
    const buttons = panels.map((panel, i) => {
      const b = h('button', { type: 'button', role: 'tab', 'aria-selected': 'false' }, panel.dataset.tab);
      b.addEventListener('click', () => select(i));
      b.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowRight') select((i + 1) % panels.length, true);
        if (e.key === 'ArrowLeft') select((i - 1 + panels.length) % panels.length, true);
      });
      bar.append(b);
      return b;
    });
    const select = (index, focus = false) => {
      panels.forEach((p, i) => { p.hidden = i !== index; });
      buttons.forEach((b, i) => {
        b.setAttribute('aria-selected', String(i === index));
        b.tabIndex = i === index ? 0 : -1;
      });
      if (focus) buttons[index].focus();
    };
    this.prepend(bar);
    select(0);
  }
}

for (const [name, cls] of [
  ['w-header', WHeader],
  ['w-footer', WFooter],
  ['w-status', WStatus],
  ['w-score', WScore],
  ['w-copy', WCopy],
  ['w-tabs', WTabs],
]) {
  if (!customElements.get(name)) customElements.define(name, cls);
}

/** Build a tab set from { label: code } without touching innerHTML. */
export function codeTabs(snippets, labels = {}) {
  const tabs = document.createElement('w-tabs');
  for (const [key, code] of Object.entries(snippets)) {
    const section = h('section', { 'data-tab': labels[key] || key });
    const copy = document.createElement('w-copy');
    copy.textContent = code;
    section.append(copy);
    tabs.append(section);
  }
  return tabs;
}
