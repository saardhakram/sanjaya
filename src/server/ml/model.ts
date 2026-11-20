import { FEATURES, groupIndices, type FeatureGroup, type FeatureSpec } from './features.js';
import { anomalyScore, type ForestModel } from './iforest.js';
import { DRISHTI_MODEL } from './model.generated.js';

/**
 * Drishti scores each IP with two unsupervised signals per traffic group:
 *
 *  1. Isolation Forest: how *jointly* rare the behaviour is. It is good at odd
 *     combinations, but by construction a point far outside the training range
 *     scores no higher than the most extreme training point.
 *  2. Tail distance: how far the most extreme feature sits beyond the benign
 *     99th percentile, in units of the benign spread. It keeps growing the
 *     further outside normal an IP goes (20 ports instead of 2).
 *
 * evidence = forestSignal + tailSignal, and the group's threshold is
 * calibrated so only 0.1% of benign training clients reach it.
 */

/** One forest and calibration per feature group (logins, web, firewall). */
export interface GroupModel {
  group: FeatureGroup;
  trainingRows: number;
  /** Median forest score of benign clients. */
  forestMedian: number;
  /** Forest score that 99% of benign clients stay below. */
  forestP99: number;
  /** Evidence at or above this is flagged (benign 99.9th percentile, never below 1). */
  threshold: number;
  forest: ForestModel;
}

/** Everything the trained model needs at inference time. Produced by scripts/train-drishti.ts. */
export interface DrishtiModel {
  version: string;
  featureKeys: string[];
  trainingProfiles: number;
  groups: GroupModel[];
  /** Per feature, the 0th…100th percentiles among benign IPs with that group's traffic (model-input scale). */
  percentiles: number[][];
  /** Per feature, the benign 95th percentile on the human scale, for explanations. */
  typical: number[];
}

export interface Reason {
  feature: string;
  label: string;
  /** This IP's value, formatted for people (e.g. "94%", "15"). */
  value: string;
  /** What 95% of normal clients stay at or below, formatted the same way. */
  typical: string;
  group: FeatureGroup;
}

export interface GroupScore {
  group: FeatureGroup;
  forestScore: number;
  evidence: number;
  threshold: number;
}

export interface Verdict {
  /** 0–100; 50 is the flagging threshold, 100 is twice the evidence needed. */
  score: number;
  anomalous: boolean;
  /** The group with the strongest evidence relative to its threshold. */
  top: GroupScore;
  scores: GroupScore[];
  reasons: Reason[];
}

/** Benign-spread units beyond p99 that add 1.0 of evidence. */
const TAIL_UNIT = 3;

export function formatValue(spec: FeatureSpec, raw: number): string {
  if (spec.scale === 'ratio') return `${Math.round(raw * 100)}%`;
  if (spec.scale === 'chars') return `${Math.round(raw)} chars`;
  return String(Math.round(raw));
}

/** Fraction of training values below `v`, interpolated from stored percentiles. */
export function percentileRank(percentiles: readonly number[], v: number): number {
  const last = percentiles.length - 1;
  if (v < percentiles[0]!) return 0;
  if (v >= percentiles[last]!) return 1;
  let i = 0;
  while (i < last && percentiles[i + 1]! <= v) i++;
  const lo = percentiles[i]!;
  const hi = percentiles[i + 1]!;
  const frac = hi > lo ? (v - lo) / (hi - lo) : 0;
  return (i + frac) / last;
}

/** How far above the benign 99th percentile a feature value sits, in benign-spread units. */
export function excess(percentiles: readonly number[], v: number): number {
  const spread = Math.max(percentiles[99]! - percentiles[50]!, 0.05);
  return (v - percentiles[99]!) / spread;
}

/** Evidence for one group: forest signal plus tail signal. Shared by training and scoring. */
export function groupEvidence(
  model: Pick<DrishtiModel, 'percentiles'>,
  g: Pick<GroupModel, 'group' | 'forest' | 'forestMedian' | 'forestP99'>,
  vector: readonly number[],
): { forestScore: number; evidence: number } {
  const idx = groupIndices(g.group);
  const forestScore = anomalyScore(
    g.forest,
    idx.map((i) => vector[i]!),
  );
  const forestSignal =
    (forestScore - g.forestMedian) / Math.max(g.forestP99 - g.forestMedian, 1e-6);
  const tail = Math.max(0, ...idx.map((i) => excess(model.percentiles[i]!, vector[i]!)));
  return { forestScore, evidence: forestSignal + tail / TAIL_UNIT };
}

/**
 * Why an IP looks unusual: the features (within the given groups) where it
 * sits furthest above what normal clients do.
 */
export function explain(
  model: DrishtiModel,
  vector: readonly number[],
  raw: readonly number[],
  groups: readonly FeatureGroup[],
): Reason[] {
  return groups
    .flatMap(groupIndices)
    .map((i) => ({
      i,
      rank: percentileRank(model.percentiles[i]!, vector[i]!),
      excess: excess(model.percentiles[i]!, vector[i]!),
    }))
    .filter((r) => r.rank >= 0.97 && raw[r.i]! > model.typical[r.i]!)
    .sort((a, b) => b.excess - a.excess)
    .slice(0, 3)
    .map(({ i }) => {
      const spec = FEATURES[i]!;
      return {
        feature: spec.key,
        label: spec.label,
        value: formatValue(spec, raw[i]!),
        typical: `≤ ${formatValue(spec, model.typical[i]!)}`,
        group: spec.group,
      };
    });
}

/** Scores one IP with every group whose kind of traffic it has. */
export function judge(
  vector: readonly number[],
  raw: readonly number[],
  groups: readonly FeatureGroup[],
  model: DrishtiModel = DRISHTI_MODEL,
): Verdict | null {
  const scores: GroupScore[] = model.groups
    .filter((g) => groups.includes(g.group))
    .map((g) => ({ group: g.group, threshold: g.threshold, ...groupEvidence(model, g, vector) }));
  if (scores.length === 0) return null;
  const rel = (s: GroupScore): number => s.evidence / s.threshold;
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
