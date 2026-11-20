import { benignProfiles } from './baseline.js';
import { FEATURES, GROUPS, groupIndices, type EntityProfile } from './features.js';
import { anomalyScore, fitForest } from './iforest.js';
import { groupEvidence, type DrishtiModel, type GroupModel } from './model.js';

/** Training settings. Changing any of them changes the model, so bump the version too. */
export const TRAINING = {
  version: 'drishti-1.0',
  baselineProfiles: 4000,
  baselineSeed: 1108, // Bhagavad Gita 11.8: "I give you divine sight"
  forestSeed: 18,
  trees: 100,
  sampleSize: 256,
  /** Flag only evidence above this share of benign training clients. */
  thresholdQuantile: 0.999,
  /** Never flag below this much evidence, however the quantile lands. */
  minThreshold: 1,
} as const;

function quantile(sorted: readonly number[], q: number): number {
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (pos - lo);
}

const round = (n: number, digits: number): number => Number(n.toFixed(digits));

export interface GroupReport {
  group: string;
  rows: number;
  evidenceP50: number;
  evidenceP99: number;
  evidenceMax: number;
  threshold: number;
  falsePositiveRate: number;
}

/** Fits one forest per feature group on benign profiles (synthetic + any provided) and calibrates each threshold. */
export function trainDrishti(extra: readonly EntityProfile[] = []): {
  model: DrishtiModel;
  report: GroupReport[];
} {
  const profiles = [...benignProfiles(TRAINING.baselineProfiles, TRAINING.baselineSeed), ...extra];
  const percentiles = FEATURES.map((spec, f) => {
    const column = profiles
      .filter((p) => p.groups.includes(spec.group))
      .map((p) => p.vector[f]!)
      .sort((a, b) => a - b);
    return Array.from({ length: 101 }, (_, p) => round(quantile(column, p / 100), 4));
  });
  const typical = FEATURES.map((spec, f) => {
    const column = profiles
      .filter((p) => p.groups.includes(spec.group))
      .map((p) => p.raw[f]!)
      .sort((a, b) => a - b);
    return round(quantile(column, 0.95), 4);
  });
  const report: GroupReport[] = [];
  const groups: GroupModel[] = GROUPS.map((group, gi) => {
    const idx = groupIndices(group);
    const members = profiles.filter((p) => p.groups.includes(group));
    const forest = fitForest(
      members.map((p) => idx.map((i) => p.vector[i]!)),
      { trees: TRAINING.trees, sampleSize: TRAINING.sampleSize, seed: TRAINING.forestSeed + gi },
    );
    const forestScores = members
      .map((p) =>
        anomalyScore(
          forest,
          idx.map((i) => p.vector[i]!),
        ),
      )
      .sort((a, b) => a - b);
    const calibrated = {
      group,
      forest,
      forestMedian: round(quantile(forestScores, 0.5), 4),
      forestP99: round(quantile(forestScores, 0.99), 4),
    };
    const evidence = members
      .map((p) => groupEvidence({ percentiles }, calibrated, p.vector).evidence)
      .sort((a, b) => a - b);
    const threshold = round(
      Math.max(TRAINING.minThreshold, quantile(evidence, TRAINING.thresholdQuantile)),
      3,
    );
    report.push({
      group,
      rows: members.length,
      evidenceP50: quantile(evidence, 0.5),
      evidenceP99: quantile(evidence, 0.99),
      evidenceMax: evidence[evidence.length - 1]!,
      threshold,
      falsePositiveRate: evidence.filter((e) => e >= threshold).length / evidence.length,
    });
    return { ...calibrated, trainingRows: members.length, threshold };
  });
  return {
    model: {
      version: TRAINING.version,
      featureKeys: FEATURES.map((f) => f.key),
      trainingProfiles: profiles.length,
      groups: groups.map(({ group, trainingRows, forestMedian, forestP99, threshold, forest }) => ({
        group,
        trainingRows,
        forestMedian,
        forestP99,
        threshold,
        forest,
      })),
      percentiles,
      typical,
    },
    report,
  };
}
