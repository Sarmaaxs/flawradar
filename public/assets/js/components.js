// Small set of custom elements used across the pages.
// All of them render into the page itself (no shadow DOM) so the stylesheet applies.

import { countUp, stagger } from './motion.js';
import { h } from './dom.js';

const NAV = [
  ['scan', '/', 'Scan'],
  ['whitelist', '/whitelist', 'Whitelist'],
  ['source', '/source', 'Source code'],
  ['intel', '/intel', 'Beta'],
  ['verify', '/verify', 'Verify'],
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
      h(
        'header',
        { class: 'site-head' },
        // The space and the dash are real text, so the name reads "FlawRadar - Web Security Checker" everywhere.
        h('div', { class: 'brand' }, h('a', { href: '/' }, 'FlawRadar'), ' ', h('span', { class: 'tag' }, '— Web Security Checker')),
        nav,
      ),
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
        h(
          'p',
          {},
          h('a', { href: '/terms' }, 'Terms of Service'), ' | ',
          h('a', { href: '/acceptable-use' }, 'Acceptable Use'), ' | ',
          h('a', { href: '/privacy' }, 'Privacy'), ' | ',
          h('a', { href: '/about' }, 'About'),
        ),
        h('p', {}, 'Test only what you own or have written permission to test. Reports are information, not a guarantee of security.'),
      ),
    );
  }
}

/** <w-status value="fail"> prints [FAIL]. The value sets the colour; label, if given, sets the text. */
class WStatus extends HTMLElement {
  static observedAttributes = ['value', 'label'];
  connectedCallback() { this.render(); }
  attributeChangedCallback() { this.render(); }
  render() {
    const v = this.getAttribute('label') || this.getAttribute('value') || '';
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
    fill.style.setProperty('--fill', String(score / 100));
    const points = h('span', { class: 'points' }, `${score} out of 100`);
    this._stop?.();
    this._stop = countUp((n) => { points.textContent = `${n} out of 100`; }, score, 900);
    this.replaceChildren(
      h(
        'div',
        { class: 'scorebox' },
        h('span', { class: 'grade' }, this.getAttribute('grade') || '?'),
        points,
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
      button.classList.add('copied');
      setTimeout(() => {
        button.textContent = 'Copy';
        button.classList.remove('copied');
      }, 1500);
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

const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', '.hg', 'vendor', 'dist', 'build', '.next', '.nuxt', '.cache', '__pycache__', 'venv', '.venv', 'bower_components', 'coverage', '.idea', '.vscode', 'target']);

/** Read a dropped directory tree. Folders such as node_modules are not entered. */
async function walk(entry, prefix, out, skipped) {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    out.push({ path: prefix + entry.name, file });
  } else if (entry.isDirectory) {
    if (SKIP_DIRS.has(entry.name)) {
      skipped.add(entry.name);
      return;
    }
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (!batch.length) break;
      for (const child of batch) await walk(child, `${prefix}${entry.name}/`, out, skipped);
    }
  }
}

/**
 * <w-dropzone>: drop files, a folder or a .zip, or use the buttons.
 * Fires "w-files" with detail { files: [{ path, file }], skippedDirs: [name] }.
 */
class WDropzone extends HTMLElement {
  connectedCallback() {
    if (this._built) return;
    this._built = true;

    const pick = (attrs) => {
      const input = h('input', { type: 'file', hidden: true, ...attrs });
      input.addEventListener('change', () => {
        const files = [...input.files].map((file) => ({ path: file.webkitRelativePath || file.name, file }));
        input.value = '';
        this.emit(files, new Set());
      });
      return input;
    };
    const fileList = h('ul', { class: 'dropzone-files', 'aria-live': 'polite', hidden: true });
    this._fileList = fileList;
    const filesInput = pick({ multiple: true, id: 'pick-files' });
    const folderInput = pick({ webkitdirectory: true, id: 'pick-folder' });

    const box = h(
      'div',
      { class: 'dropzone', tabindex: '0', role: 'button', 'aria-label': 'Drop your source code here, or press Enter to choose files' },
      h('p', { class: 'dz-title' }, 'Drop your source code here'),
      h('p', { class: 'muted' }, 'A folder, some files, or one .zip'),
    );
    const buttons = h(
      'p',
      { class: 'dz-buttons' },
      h('button', { type: 'button', id: 'btn-folder' }, 'Choose folder'),
      ' ',
      h('button', { type: 'button', id: 'btn-files' }, 'Choose files or zip'),
    );
    buttons.querySelector('#btn-folder').addEventListener('click', () => folderInput.click());
    buttons.querySelector('#btn-files').addEventListener('click', () => filesInput.click());
    box.addEventListener('click', () => filesInput.click());
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        filesInput.click();
      }
    });

    for (const type of ['dragenter', 'dragover']) {
      box.addEventListener(type, (e) => {
        e.preventDefault();
        box.classList.add('over');
      });
    }
    box.addEventListener('dragleave', () => box.classList.remove('over'));
    box.addEventListener('drop', async (e) => {
      e.preventDefault();
      box.classList.remove('over');
      // The item list is emptied once this handler yields, so take everything first.
      const items = [...(e.dataTransfer?.items || [])].filter((i) => i.kind === 'file');
      const taken = items.map((item) => ({ entry: item.webkitGetAsEntry?.() || null, file: item.getAsFile() }));
      const out = [];
      const skipped = new Set();
      try {
        for (const { entry, file } of taken) {
          if (entry) await walk(entry, '', out, skipped);
          else if (file) out.push({ path: file.webkitRelativePath || file.name, file });
        }
      } catch {
        /* an unreadable entry is skipped; the rest still counts */
      }
      this.emit(out, skipped);
    });

    this.replaceChildren(box, buttons, fileList, filesInput, folderInput);
  }

  emit(files, skippedDirs) {
    if (this._fileList) {
      const shown = files.slice(0, 8).map(({ path }) => h('li', {}, path));
      if (files.length > 8) shown.push(h('li', {}, `and ${files.length - 8} more`));
      this._fileList.replaceChildren(...shown);
      this._fileList.hidden = files.length === 0;
      stagger(shown);
    }
    this.dispatchEvent(new CustomEvent('w-files', { detail: { files, skippedDirs: [...skippedDirs] } }));
  }
}

for (const [name, cls] of [
  ['w-dropzone', WDropzone],
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