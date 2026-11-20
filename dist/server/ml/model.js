import { FEATURES, groupIndices } from './features.js';
import { anomalyScore } from './iforest.js';
import { DRISHTI_MODEL } from './model.generated.js';
/** Benign-spread units beyond p99 that add 1.0 of evidence. */
const TAIL_UNIT = 3;
export function formatValue(spec, raw) {
    if (spec.scale === 'ratio')
        return `${Math.round(raw * 100)}%`;
    if (spec.scale === 'chars')
        return `${Math.round(raw)} chars`;
    return String(Math.round(raw));
}
/** Fraction of training values below `v`, interpolated from stored percentiles. */
export function percentileRank(percentiles, v) {
    const last = percentiles.length - 1;
    if (v < percentiles[0])
        return 0;
    if (v >= percentiles[last])
        return 1;
    let i = 0;
    while (i < last && percentiles[i + 1] <= v)
        i++;
    const lo = percentiles[i];
    const hi = percentiles[i + 1];
    const frac = hi > lo ? (v - lo) / (hi - lo) : 0;
    return (i + frac) / last;
}
/** How far above the benign 99th percentile a feature value sits, in benign-spread units. */
export function excess(percentiles, v) {
    const spread = Math.max(percentiles[99] - percentiles[50], 0.05);
    return (v - percentiles[99]) / spread;
}
/** Evidence for one group: forest signal plus tail signal. Shared by training and scoring. */
export function groupEvidence(model, g, vector) {
    const idx = groupIndices(g.group);
    const forestScore = anomalyScore(g.forest, idx.map((i) => vector[i]));
    const forestSignal = (forestScore - g.forestMedian) / Math.max(g.forestP99 - g.forestMedian, 1e-6);
    const tail = Math.max(0, ...idx.map((i) => excess(model.percentiles[i], vector[i])));
    return { forestScore, evidence: forestSignal + tail / TAIL_UNIT };
}
/**
 * Why an IP looks unusual: the features (within the given groups) where it
 * sits furthest above what normal clients do.
 */
export function explain(model, vector, raw, groups) {
    return groups
        .flatMap(groupIndices)
        .map((i) => ({
        i,
        rank: percentileRank(model.percentiles[i], vector[i]),
        excess: excess(model.percentiles[i], vector[i]),
    }))
        .filter((r) => r.rank >= 0.97 && raw[r.i] > model.typical[r.i])
        .sort((a, b) => b.excess - a.excess)
        .slice(0, 3)
        .map(({ i }) => {
        const spec = FEATURES[i];
        return {
            feature: spec.key,
            label: spec.label,
            value: formatValue(spec, raw[i]),
            typical: `≤ ${formatValue(spec, model.typical[i])}`,
            group: spec.group,
        };
    });
}
/** Scores one IP with every group whose kind of traffic it has. */
export function judge(vector, raw, groups, model = DRISHTI_MODEL) {
    const scores = model.groups
        .filter((g) => groups.includes(g.group))
        .map((g) => ({ group: g.group, threshold: g.threshold, ...groupEvidence(model, g, vector) }));
    if (scores.length === 0)
        return null;
    const rel = (s) => s.evidence / s.threshold;
    const top = scores.reduce((a, b) => (rel(b) > rel(a) ? b : a));
    const flagged = scores.filter((s) => rel(s) >= 1).map((s) => s.group);
    const anomalous = flagged.length > 0;
    return {
        score: Math.max(0, Math.min(100, Math.round(50 * rel(top)))),
        anomalous,
        top,
        scores,
        reasons: explain(model, vector, raw, anomalous ? flagged : groups),
    };
}
export { DRISHTI_MODEL };
