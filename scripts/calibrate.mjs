// Scans every site in calibration/sites.txt through a running FlawRadar and writes a table to read.
// Start the server first (npm start), then:   node scripts/calibrate.mjs [http://127.0.0.1:3000]
// For each site, ask: does the grade match what you know about it? Write down every result that looks
// wrong. Those are the false alarms and misses to fix first.
import { readFileSync, writeFileSync } from 'node:fs';

const base = process.argv[2] || 'http://127.0.0.1:3000';
const sites = readFileSync(new URL('../calibration/sites.txt', import.meta.url), 'utf8')
  .split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean);

const json = async (path, options) => {
  const res = await fetch(base + path, { ...options, headers: { 'content-type': 'application/json', ...(options?.headers || {}) } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error?.message || body.message || `HTTP ${res.status}`);
  return body;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const { termsVersion } = await json('/api/scanner');
const rows = [];
for (const host of sites) {
  process.stdout.write(`${host} ... `);
  try {
    const { id } = await json('/api/scans', { method: 'POST', body: JSON.stringify({ url: host, deep: false, terms: termsVersion }) });
    let scan;
    for (let i = 0; i < 60; i += 1) {
      await sleep(1500);
      scan = await json(`/api/scans/${id}`);
      if (scan.status === 'done' || scan.status === 'failed') break;
    }
    if (scan.status !== 'done') { rows.push({ host, grade: '-', score: '-', risk: '-', failed: scan.error || scan.status }); console.log(scan.status); continue; }
    const r = scan.result;
    const failed = r.findings.filter((f) => f.status === 'fail').map((f) => f.title);
    rows.push({ host, grade: r.blocked ? 'blocked' : r.grade, score: r.score, risk: r.exposure ? `${r.exposure.percent}%` : '-', failed: failed.slice(0, 6).join('; ') || 'none' });
    console.log(r.grade);
  } catch (err) {
    rows.push({ host, grade: '-', score: '-', risk: '-', failed: err.message });
    console.log(err.message);
  }
  await sleep(3000); // be gentle, and stay inside the per-visitor limits
}

const date = new Date().toISOString().slice(0, 10);
const table = ['| Site | Grade | Score | Modelled risk | Failed checks |', '|---|---|---|---|---|', ...rows.map((r) => `| ${r.host} | ${r.grade} | ${r.score} | ${r.risk} | ${r.failed} |`)].join('\n');
const out = new URL(`../calibration/report-${date}.md`, import.meta.url);
writeFileSync(out, `# Calibration run ${date}\n\n${table}\n\nMark each row: right, too harsh, too soft, or wrong check. Fix the wrong ones first.\n`);
console.log(`\n${table}\n\nSaved to calibration/report-${date}.md`);
