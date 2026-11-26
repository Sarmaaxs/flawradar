import './components.js';
import { api, h, scannerInfo, rememberedTerms, rememberTerms, forgetTerms } from './dom.js';

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

// Watch signup lives inside Verify so ownership proof and monitoring are one workflow.
const watchToggle = $('#show-watch');
const watchPanel = $('#watch-panel');
watchToggle?.addEventListener('click', () => {
  const opening = watchPanel.hidden;
  watchPanel.hidden = !opening;
  watchToggle.setAttribute('aria-expanded', String(opening));
  watchToggle.textContent = opening ? 'Hide monitoring form' : 'Set up monitoring';
  if (opening && current?.host) $('#watch-host').value = current.host;
});

let watchTermsVersion = null;
try {
  const info = await scannerInfo();
  watchTermsVersion = info.termsVersion;
  if (rememberedTerms() === watchTermsVersion) $('#watch-terms').checked = true;
  else if (rememberedTerms()) forgetTerms();
  if (!info.watches.enabled) {
    $('#watch-off').hidden = false;
    $('#watch-submit').disabled = true;
  }
} catch { /* API will show a useful error when submitted */ }

$('#verify-watch-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const out = $('#watch-error');
  const done = $('#watch-done');
  out.hidden = true; done.hidden = true;
  if (!$('#watch-terms').checked) {
    out.textContent = 'Please confirm that you are authorized to monitor this site and accept the Terms.';
    out.hidden = false; $('#watch-terms').focus(); return;
  }
  const button = $('#watch-submit');
  button.disabled = true; button.textContent = 'Sending confirmation…';
  try {
    const host = $('#watch-host').value.trim();
    const email = $('#watch-email').value.trim();
    const r = await api('/api/watch', { method: 'POST', body: JSON.stringify({ url: host, email, terms: watchTermsVersion }) });
    rememberTerms(watchTermsVersion);
    done.textContent = `Confirmation email sent to ${email}. Open its link to start monitoring ${r.host}. Check spam if it does not arrive.`;
    done.hidden = false;
  } catch (err) {
    out.textContent = err.code === 'needs_verification'
      ? 'This host is not verified yet. Complete the proof check above, then try again.'
      : err.message;
    out.hidden = false;
  } finally {
    button.disabled = false; button.textContent = 'Start monitoring';
  }
});
