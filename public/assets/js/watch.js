import './components.js';
import { api, forgetTerms, rememberTerms, rememberedTerms, scannerInfo } from './dom.js';

const $ = (sel) => document.querySelector(sel);
const params = new URLSearchParams(location.search);
const mode = location.pathname.endsWith('/confirm') ? 'confirm' : location.pathname.endsWith('/stop') ? 'stop' : 'form';

$('#mode-form').hidden = mode !== 'form';
$('#mode-confirm').hidden = mode !== 'confirm';
$('#mode-stop').hidden = mode !== 'stop';

// The link in the email carries the id and the secret. They are sent in the request body, never kept.
const link = { id: params.get('id') || '', s: params.get('s') || '' };

function say(el, text, isError) {
  el.textContent = text;
  el.hidden = false;
  el.className = isError ? 'alert' : 'notice';
}

if (mode === 'confirm') {
  $('#confirm').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const r = await api('/api/watch/confirm', { method: 'POST', body: JSON.stringify(link) });
      $('#confirm-host').textContent = r.host;
      say($('#confirm-out'), `Done. ${r.host} will be scanned within a few minutes to set the baseline, then about every ${r.intervalHours} hours. You will only get an email when the grade gets worse.`, false);
    } catch (err) {
      button.disabled = false;
      say($('#confirm-out'), err.message, true);
    }
  });
} else if (mode === 'stop') {
  $('#stop').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const r = await api('/api/watch/stop', { method: 'POST', body: JSON.stringify(link) });
      say($('#stop-out'), `Stopped. ${r.host} is no longer watched and your address was removed from it.`, false);
    } catch (err) {
      button.disabled = false;
      say($('#stop-out'), err.message, true);
    }
  });
} else {
  const host = params.get('host');
  if (host) $('#host').value = host;
  let termsVersion = null;
  try {
    const info = await scannerInfo();
    termsVersion = info.termsVersion;
    $('#interval').textContent = String(info.watches.intervalHours);
    if (!info.watches.enabled) {
      $('#off').hidden = false;
      $('#go').disabled = true;
    }
    if (rememberedTerms() === termsVersion) $('#terms').checked = true;
    else if (rememberedTerms()) forgetTerms();
  } catch {
    /* the server will say so when the form is sent */
  }
  $('#terms').addEventListener('change', () => $('#consent-box').classList.remove('attention'));

  $('#watch-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    $('#error').hidden = true;
    $('#done').hidden = true;
    if (!$('#terms').checked) {
      $('#consent-box').classList.add('attention');
      $('#terms').focus();
      return say($('#error'), 'Please confirm that you may scan this site and accept the terms first.', true);
    }
    const button = $('#go');
    button.disabled = true;
    try {
      const r = await api('/api/watch', {
        method: 'POST',
        body: JSON.stringify({ url: $('#host').value.trim(), email: $('#email').value.trim(), terms: termsVersion }),
      });
      rememberTerms(termsVersion);
      say($('#done'), `Check the inbox of ${$('#email').value.trim()}. The confirmation link starts the watch of ${r.host}. If nothing arrives in a few minutes, look in the spam folder.`, false);
    } catch (err) {
      if (err.code === 'needs_verification') {
        say($('#error'), `${err.message} Add the proof on the Verify page first, then come back.`, true);
      } else {
        say($('#error'), err.message, true);
      }
    } finally {
      button.disabled = false;
    }
  });
}
