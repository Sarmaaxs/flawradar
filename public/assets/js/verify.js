import './components.js';
import { api, h } from './dom.js';

const $ = (sel) => document.querySelector(sel);
const input = $('#host');
const error = $('#error');
let current = null;

const prefill = new URLSearchParams(location.search).get('host');
if (prefill) input.value = prefill;

function showError(message) {
  error.textContent = message;
  error.hidden = false;
}

async function load() {
  error.hidden = true;
  const value = input.value.trim();
  if (!value) return showError('Enter a host name.');
  try {
    const data = await api('/api/verify', { method: 'POST', body: JSON.stringify({ host: value }) });
    current = data;
    input.value = data.host;
    $('#file-url').textContent = data.file.path;
    // w-copy renders once when connected, so replace it rather than edit it.
    const copy = document.createElement('w-copy');
    copy.id = 'file-value';
    copy.setAttribute('label', 'file contents');
    copy.textContent = data.file.content;
    $('#file-value').replaceWith(copy);
    $('#dns-name').textContent = data.dns.name;
    $('#dns-value').textContent = data.dns.value;
    $('#outcome').hidden = true;
    $('#proof').hidden = false;
  } catch (err) {
    $('#proof').hidden = true;
    showError(err.message);
  }
}

$('#verify-form').addEventListener('submit', (event) => {
  event.preventDefault();
  load();
});

$('#check').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const out = $('#outcome');
  button.disabled = true;
  button.textContent = 'Checking...';
  try {
    const r = await api('/api/verify/check', { method: 'POST', body: JSON.stringify({ host: current.host }) });
    if (r.verified) {
      out.replaceChildren(
        h(
          'p',
          { class: 'alert note' },
          h('b', {}, 'Verified. '),
          `FlawRadar found the proof for ${r.host} (${r.method === 'file' ? 'file' : 'DNS record'}). `,
          h('a', { href: `/?url=${encodeURIComponent(r.host)}` }, 'Run a deep scan.'),
        ),
      );
    } else {
      out.replaceChildren(
        h('p', { class: 'alert' }, h('b', {}, 'Not found yet. '), 'Here is what FlawRadar tried:'),
        h(
          'table',
          {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Method'), h('th', {}, 'Where'), h('th', {}, 'Result'))),
          h('tbody', {}, ...r.tried.map((t) => h('tr', {}, h('td', {}, t.method), h('td', { class: 'mono' }, t.where), h('td', {}, t.result)))),
        ),
      );
    }
    out.hidden = false;
  } catch (err) {
    out.replaceChildren(h('p', { class: 'alert' }, err.message));
    out.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = 'Check now';
  }
});

if (prefill) load();
