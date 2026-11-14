import './components.js';
import { api } from './dom.js';

// Fills the operator's details into the legal pages. Anything not configured
// stays as a highlighted placeholder, so unfinished text is easy to spot.
try {
  const info = await api('/api/scanner');
  const values = { ...info.legal, ...info.limits, termsVersion: info.termsVersion, baseUrl: info.baseUrl };
  document.querySelectorAll('[data-legal]').forEach((el) => {
    const value = values[el.dataset.legal];
    if (value !== null && value !== undefined && value !== '') {
      el.textContent = String(value);
      el.classList.remove('unset');
    } else {
      el.classList.add('unset');
    }
  });
} catch {
  /* the page still reads correctly with its placeholders */
}