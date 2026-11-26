import './components.js';
import { api } from './dom.js';

// Fills configured operator details. Unknown provider details are described transparently in the policy.
try {
  const info = await api('/api/scanner');
  const values = { ...info.legal, ...info.limits, termsVersion: info.termsVersion, baseUrl: location.origin };
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