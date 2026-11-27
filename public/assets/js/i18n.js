// Built-in translation. No third party and no cookies: language files live in /assets/i18n/, the page
// text is swapped in the browser, and the choice is kept in localStorage. Text with no translation
// stays in English, so a missing line never breaks a page.

const STORE = 'flawradar-lang';
const SKIP = new Set(['SCRIPT', 'STYLE', 'PRE', 'CODE', 'TEXTAREA', 'W-COPY']);
const ATTRS = ['placeholder', 'aria-label', 'title', 'alt'];

const original = new WeakMap();      // text node -> its English text
const originalAttr = new WeakMap();  // element -> { attribute: English text }
let dictionary = {};
let current = 'en';
let observer = null;

// Spaces and curly apostrophes are ignored when matching, so layout and typography do not matter.
export const normalise = (text) => text.replace(/[‘’]/g, "'").replace(/\s+/g, ' ').trim();

const read = (key) => { try { return localStorage.getItem(key); } catch { return null; } };
const write = (key, value) => { try { localStorage.setItem(key, value); } catch { /* the choice just is not remembered */ } };

function lookup(text) {
  const key = normalise(text);
  return key ? dictionary[key] : undefined;
}

function translateText(node) {
  const english = original.get(node) ?? node.nodeValue;
  const hit = current === 'en' ? undefined : lookup(english);
  if (hit === undefined) {
    if (original.has(node)) { node.nodeValue = original.get(node); original.delete(node); }
    return;
  }
  original.set(node, english);
  const lead = /^\s*/.exec(english)[0];
  const tail = /\s*$/.exec(english)[0];
  node.nodeValue = `${lead}${hit}${tail}`;
}

function translateAttributes(el) {
  const saved = originalAttr.get(el) || {};
  for (const name of ATTRS) {
    if (!el.hasAttribute(name)) continue;
    const english = saved[name] ?? el.getAttribute(name);
    const hit = current === 'en' ? undefined : lookup(english);
    if (hit === undefined) {
      if (name in saved) { el.setAttribute(name, saved[name]); delete saved[name]; }
    } else {
      saved[name] = english;
      el.setAttribute(name, hit);
    }
  }
  if (Object.keys(saved).length) originalAttr.set(el, saved);
}

export function apply(root = document.body) {
  if (!root) return;
  if (root.nodeType === Node.TEXT_NODE) { if (!SKIP.has(root.parentElement?.tagName)) translateText(root); return; }
  if (root.nodeType !== Node.ELEMENT_NODE || SKIP.has(root.tagName)) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
    acceptNode: (n) => (n.nodeType === Node.ELEMENT_NODE && SKIP.has(n.tagName) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
  });
  translateAttributes(root);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (n.nodeType === Node.TEXT_NODE) translateText(n);
    else translateAttributes(n);
  }
}

function watch() {
  if (observer) return;
  // Text added later (a report, an error message) is translated as it appears.
  observer = new MutationObserver((records) => {
    for (const r of records) for (const added of r.addedNodes) apply(added);
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

let languages = null;
async function languageList() {
  if (!languages) {
    try { languages = await (await fetch('/assets/i18n/index.json')).json(); } catch { languages = [{ code: 'en', name: 'English' }]; }
  }
  return languages;
}

export async function setLanguage(code) {
  const list = await languageList();
  const entry = list.find((l) => l.code === code) || list[0];
  if (entry.code === 'en') {
    dictionary = {};
  } else {
    try {
      const raw = await (await fetch(`/assets/i18n/${entry.code}.json`)).json();
      dictionary = Object.fromEntries(Object.entries(raw).map(([k, v]) => [normalise(k), v]));
    } catch {
      return; // keep the current language if the file cannot be loaded
    }
  }
  current = entry.code;
  document.documentElement.lang = entry.code;
  document.documentElement.dir = entry.dir || 'ltr';
  write(STORE, entry.code);
  apply(document.body);
  watch();
}

/** Fills the header's language box and applies the saved language. Safe to call more than once. */
export async function initLanguageSelector() {
  const picker = document.getElementById('flawradar-language');
  if (!picker || picker.dataset.ready) return;
  picker.dataset.ready = '1';
  const list = await languageList();
  picker.append(...list.map((l) => {
    const option = document.createElement('option');
    option.value = l.code;
    option.textContent = l.name;
    return option;
  }));
  const saved = read(STORE);
  if (saved && saved !== 'en') { picker.value = saved; await setLanguage(saved); }
  picker.addEventListener('change', () => { if (picker.value) setLanguage(picker.value); });
}
