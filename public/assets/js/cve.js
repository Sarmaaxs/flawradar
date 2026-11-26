import './components.js';
const q = new URLSearchParams(location.search);
const get = (key, fallback='Not provided') => (q.get(key) || fallback).slice(0, 4000);
const id = get('id', 'Dependency vulnerability');
document.title = id + ' analysis - FlawRadar';
document.querySelector('#cve-title').textContent = id;
const meta = document.querySelector('#cve-meta');
for (const value of [get('package'), 'Version ' + get('version'), get('ecosystem'), 'Severity ' + get('severity')]) {
  const span = document.createElement('span'); span.textContent = value; meta.append(span);
}
document.querySelector('#cve-summary').textContent = get('summary', 'The dependency was matched against the OSV vulnerability database. Consult the linked advisory for technical details and affected conditions.');
document.querySelector('#cve-location').textContent = 'Detected in ' + get('file') + ' at line ' + get('line', '1') + '.';
document.querySelector('#cve-fix').textContent = get('fix', 'Upgrade to a vendor-confirmed fixed version. If no fixed release exists, apply vendor mitigation and reassess exposure.');

document.querySelector('#cve-details').textContent = get('details', 'No detailed advisory text was returned. Use the primary advisory reference to confirm the technical conditions.');
const ranges = document.querySelector('#cve-ranges');
try { ranges.textContent = JSON.stringify(JSON.parse(get('ranges', '[]')), null, 2); } catch { ranges.textContent = 'Advisory range data could not be parsed.'; }
const refs = document.querySelector('#cve-references');
try {
  const list = JSON.parse(get('refs', '[]'));
  if (!Array.isArray(list) || !list.length) refs.textContent = 'No external references were provided.';
  else for (const item of list.slice(0, 4)) {
    if (!item || typeof item.url !== 'string' || !/^https:\/\//i.test(item.url)) continue;
    const li = document.createElement('li'); const a = document.createElement('a');
    a.href = item.url; a.textContent = item.type || 'Advisory reference'; a.rel = 'noopener noreferrer'; a.target = '_blank';
    li.append(a); refs.append(li);
  }
} catch { refs.textContent = 'Reference data could not be parsed.'; }
