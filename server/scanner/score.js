const WEIGHT = { critical: 30, high: 15, medium: 8, low: 3 };
const GRADES = ['A', 'B', 'C', 'D', 'F'];

/**
 * Score starts at 100. A failed check costs its full weight, a warning half.
 * Checks that were skipped or only informational cost nothing.
 *
 * Grade comes from the score, then is capped: any failed critical check
 * means F, any failed high check means at best C.
 */
export function summarize(findings) {
  const counts = { pass: 0, fail: 0, warn: 0, info: 0, skip: 0 };
  let penalty = 0;
  let cap = 0;
  for (const f of findings) {
    counts[f.status] += 1;
    const weight = WEIGHT[f.severity] || 0;
    if (f.status === 'fail') {
      penalty += weight;
      if (f.severity === 'critical') cap = Math.max(cap, 4);
      else if (f.severity === 'high') cap = Math.max(cap, 2);
    } else if (f.status === 'warn') {
      penalty += weight / 2;
    }
  }
  const score = Math.max(0, Math.round(100 - penalty));
  const byScore = score >= 90 ? 0 : score >= 80 ? 1 : score >= 65 ? 2 : score >= 50 ? 3 : 4;
  return { counts, score, grade: GRADES[Math.max(byScore, cap)] };
}
