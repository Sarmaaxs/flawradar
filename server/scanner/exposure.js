// Risk model. The grade answers "how many checks failed". This answers a different question:
// "how likely is it that someone gets in, given everything that is wrong at once?"
//
// Method (noisy-OR): every weakness is treated as an independent way in, with its own chance of being
// used. Chance of at least one succeeding is 1 - product(1 - p). Weaknesses that combine into a
// worse story (an injected script plus a cookie it can read) add one extra term for the combination.
// Ranking: each fix is scored by how far the total drops when that weakness is removed, so the list
// of "fix this first" is ordered by real effect, not by label.
//
// The p values are estimates set from how often each class of weakness is used in practice. This is a
// model to rank and explain, not a measured probability for one site.

const BASE = { critical: 0.45, high: 0.22, medium: 0.09, low: 0.03 };
const WARN_FACTOR = 0.4; // a warning is a weaker form of the same weakness

const open = (f) => f && (f.status === 'fail' || f.status === 'warn');

export const CHAINS = [
  {
    id: 'cookie-theft',
    name: 'Script injection plus readable session cookie',
    story: 'If an attacker gets a script onto a page, nothing stops it reading the login cookie and taking over the account.',
    needs: ['csp', 'cookie-httponly'],
    p: 0.16,
  },
  {
    id: 'downgrade',
    name: 'Visitors can be kept on plain HTTP',
    story: 'Without a forced redirect and HSTS, someone on the same network can sit between the visitor and the site and read or change the traffic.',
    needs: ['http-redirect', 'hsts'],
    p: 0.14,
  },
  {
    id: 'framed-session',
    name: 'Page can be framed and cookies travel cross-site',
    story: 'A hostile page can load yours in a hidden frame and trick a signed-in visitor into clicking things.',
    needs: ['framing', 'cookie-samesite'],
    p: 0.07,
  },
  {
    id: 'advertised-old',
    name: 'Old software that announces itself',
    story: 'The server tells everyone its exact old version, so attackers know which published holes to try first.',
    needs: ['banner', 'old-software'],
    p: 0.1,
  },
  {
    id: 'mail-spoof',
    name: 'Anyone can send mail as your domain',
    story: 'With weak SPF and DMARC, a forged email from your own address looks real to your customers.',
    needs: ['spf', 'dmarc'],
    p: 0.1,
  },
  {
    id: 'leak-to-takeover',
    name: 'Leaked secrets next to an open admin panel',
    story: 'A readable key or password file plus a reachable admin panel is a short, well-known path to taking the whole site.',
    needsAny: [['exposed-env', 'exposed-keys', 'exposed-backup', 'exposed-vcs'], ['exposed-admin']],
    p: 0.3,
  },
];

const chainActive = (chain, isOpen) =>
  chain.needs ? chain.needs.every(isOpen) : chain.needsAny.every((group) => group.some(isOpen));

function combine(terms) {
  let safe = 1;
  for (const p of terms) safe *= 1 - p;
  return 1 - safe;
}

function probabilityOf(findings, skipId = null) {
  const byId = new Map(findings.map((f) => [f.id, f]));
  const isOpen = (id) => id !== skipId && open(byId.get(id));
  const terms = [];
  for (const f of findings) {
    if (f.id === skipId || !open(f)) continue;
    const base = BASE[f.severity] || 0;
    terms.push(f.status === 'warn' ? base * WARN_FACTOR : base);
  }
  const active = CHAINS.filter((c) => chainActive(c, isOpen));
  for (const c of active) terms.push(c.p);
  return { p: combine(terms), active };
}

export function levelFor(p) {
  if (p < 0.05) return 'Low';
  if (p < 0.15) return 'Guarded';
  if (p < 0.35) return 'Elevated';
  if (p < 0.6) return 'High';
  return 'Severe';
}

const pct = (p) => Math.round(p * 1000) / 10;

/** findings: [{ id, title, status, severity }] */
export function assessRisk(findings) {
  const { p, active } = probabilityOf(findings);
  const ranked = findings
    .filter(open)
    .map((f) => {
      const after = probabilityOf(findings, f.id).p;
      return { id: f.id, title: f.title, status: f.status, severity: f.severity, reduction: pct(p - after), after: pct(after) };
    })
    .filter((r) => r.reduction > 0)
    .sort((a, b) => b.reduction - a.reduction || a.id.localeCompare(b.id));
  return {
    probability: Math.round(p * 10000) / 10000,
    percent: pct(p),
    level: levelFor(p),
    chains: active.map((c) => ({ id: c.id, name: c.name, story: c.story, p: c.p })),
    ranked,
  };
}
