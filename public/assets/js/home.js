import './components.js';
import { api, h } from './dom.js';

const form = document.getElementById('scan-form');
const input = document.getElementById('url');
const deep = document.getElementById('deep');
const button = document.getElementById('go');
const error = document.getElementById('error');

const prefill = new URLSearchParams(location.search).get('url');
if (prefill) input.value = prefill;

function showError(message, ...extra) {
  error.replaceChildren(message, ...extra);
  error.hidden = false;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  error.hidden = true;
  const value = input.value.trim();
  if (!value) {
    showError('Enter a website address.');
    input.focus();
    return;
  }
  button.disabled = true;
  button.textContent = 'Starting...';
  try {
    const { id } = await api('/api/scans', {
      method: 'POST',
      body: JSON.stringify({ url: value, deep: deep.checked }),
    });
    location.assign(`/report/${id}`);
  } catch (err) {
    if (err.code === 'needs_verification') {
      const host = err.detail?.host || value;
      showError(
        'Deep scans need proof that you control this host. ',
        h('a', { href: `/verify?host=${encodeURIComponent(host)}` }, 'Add the proof'),
        ', or untick the box to run the normal scan.',
      );
    } else {
      showError(err.message);
    }
    button.disabled = false;
    button.textContent = 'Run scan';
  }
});
