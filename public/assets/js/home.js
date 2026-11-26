import './components.js';
import { api, h, forgetTerms, rememberDeleteToken, rememberTerms, rememberedTerms, scannerInfo } from './dom.js';

const form = document.getElementById('scan-form');
const input = document.getElementById('url');
const terms = document.getElementById('terms');
const consent = document.getElementById('consent-box');
const button = document.getElementById('go');
const error = document.getElementById('error');

const prefill = new URLSearchParams(location.search).get('url');
if (prefill) input.value = prefill;

let version = null;
try {
  version = (await scannerInfo()).termsVersion;
  // Someone who accepted this exact version before does not have to tick again.
  if (rememberedTerms() === version) terms.checked = true;
  else if (rememberedTerms()) forgetTerms();
} catch {
  /* the server will say so when the form is sent */
}

function showError(message, ...extra) {
  error.replaceChildren(message, ...extra);
  error.hidden = false;
}

terms.addEventListener('change', () => consent.classList.remove('attention'));

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  error.hidden = true;
  const value = input.value.trim();
  if (!value) {
    showError('Enter a website address.');
    input.focus();
    return;
  }
  if (!terms.checked) {
    consent.classList.add('attention');
    showError('Please confirm that you may test this site and accept the terms, so FlawRadar knows the scan is authorized.');
    terms.focus();
    return;
  }
  button.disabled = true;
  button.textContent = 'Starting...';
  try {
    const { id, deleteToken } = await api('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ url: value, deep: false, terms: version }),
    });
    rememberTerms(version);
    rememberDeleteToken(id, deleteToken);
    location.assign(`/report/${id}`);
  } catch (err) {
    if (err.code === 'needs_verification') {
      const host = err.detail?.host || value;
      showError(
        'Deep checks need proof that you control this host. ',
        h('a', { href: `/verify?host=${encodeURIComponent(host)}` }, 'Add the proof'),
        ', or untick the deep checks box to run the normal scan.',
      );
    } else {
      showError(err.message);
    }
    button.disabled = false;
    button.textContent = 'Run scan';
  }
});