const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

/**
 * Transparent prioritisation heuristic, not a probability of compromise.
 * Unknown signals are omitted and the remaining weights are renormalised.
 */
export function calculateRiskPriority(finding, { exposure = 1 } = {}) {
  const components = [];
  const add = (name, value, weight) => {
    if (value === null || value === undefined || !Number.isFinite(Number(value))) return;
    components.push({ name, value: clamp(Number(value), 0, 100), weight });
  };
  const cvss = finding?.cvssBaseScore ?? finding?.cvss?.baseScore;
  if (cvss !== null && cvss !== undefined && Number.isFinite(Number(cvss))) add('cvss', Number(cvss) * 10, 0.40);
  const epss = typeof finding?.epss === 'object' ? finding.epss?.score : finding?.epss;
  if (epss !== null && epss !== undefined && Number.isFinite(Number(epss))) add('epss', Number(epss) * 100, 0.30);
  if (finding?.kev !== null && finding?.kev !== undefined) add('knownExploited', finding.kev ? 100 : 0, 0.20);
  const hasThreatSignal = components.length > 0;
  if (!hasThreatSignal) return { score: null, band: 'insufficient-data', confidenceFactor: null, components: [], model: 'weighted-priority-v1' };
  add('publicExposure', Number(exposure) * 100, 0.10);

  const weightTotal = components.reduce((sum, item) => sum + item.weight, 0);
  if (!weightTotal) return { score: null, band: 'insufficient-data', confidenceFactor: null, components, model: 'weighted-priority-v1' };
  const confidenceFactor = ({ high: 1, medium: 0.85, low: 0.65 })[finding?.confidence] ?? 0.75;
  const raw = components.reduce((sum, item) => sum + item.value * item.weight, 0) / weightTotal;
  const score = Math.round(raw * confidenceFactor);
  const band = score >= 90 ? 'critical' : score >= 75 ? 'high' : score >= 50 ? 'medium' : score >= 25 ? 'low' : 'informational';
  return {
    score, band, confidenceFactor,
    components: components.map((item) => ({ ...item, contribution: Number((item.value * item.weight / weightTotal * confidenceFactor).toFixed(2)) })),
    model: 'weighted-priority-v1',
  };
}
