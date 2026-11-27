// What changed since the last scan of the same site. Only checks that ran in both scans are compared,
// so running a deep scan after a basic one does not show every deep check as "new".

const open = (f) => f.status === 'fail' || f.status === 'warn';
const brief = (f) => ({ id: f.id, title: f.title, status: f.status, severity: f.severity });

export function diffScans(prev, curr) {
  if (!prev || !curr || !Array.isArray(prev.findings) || !Array.isArray(curr.findings)) return null;
  const before = new Map(prev.findings.map((f) => [f.id, f]));
  const out = { scoreDelta: (curr.score ?? 0) - (prev.score ?? 0), gradeFrom: prev.grade, gradeTo: curr.grade, newProblems: [], fixed: [], worse: [], better: [], newlyChecked: [], unchanged: 0 };
  for (const f of curr.findings) {
    const old = before.get(f.id);
    if (!old || old.status === 'skip') {
      if (open(f)) out.newlyChecked.push(brief(f));
      continue;
    }
    if (f.status === 'skip') continue;
    if (open(f) && !open(old)) out.newProblems.push(brief(f));
    else if (!open(f) && open(old)) out.fixed.push(brief(f));
    else if (f.status === 'fail' && old.status === 'warn') out.worse.push(brief(f));
    else if (f.status === 'warn' && old.status === 'fail') out.better.push(brief(f));
    else out.unchanged += 1;
  }
  return out;
}
