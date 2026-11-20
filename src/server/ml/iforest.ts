/**
 * Isolation Forest (Liu, Ting & Zhou, 2008), implemented from scratch so the
 * model is small, dependency-free and fully deterministic.
 *
 * Idea: anomalies are "few and different", so random axis-aligned splits
 * isolate them in fewer steps than normal points. The anomaly score is
 *   s(x) = 2^(−E[h(x)] / c(ψ))
 * where h(x) is the path length in one tree and c(ψ) the average path length
 * of an unsuccessful binary-search-tree lookup over ψ points. s ≈ 1 means
 * clearly anomalous, s ≲ 0.5 means normal.
 *
 * Trees are stored in a compact pre-order encoding:
 *   internal node → [featureIndex, threshold, leftLength, ...left, ...right]
 *   leaf          → [−size]   (size ≥ 1, so a leaf is always negative)
 * leftLength lets scoring jump straight to the right child, so scoring one
 * point costs O(depth) per tree.
 */

export type EncodedTree = number[];

export interface ForestModel {
  /** Points sampled per tree (ψ). */
  sampleSize: number;
  trees: EncodedTree[];
}

export interface FitOptions {
  trees: number;
  sampleSize: number;
  seed: number;
}

const EULER_GAMMA = 0.5772156649015329;

/** Average path length of an unsuccessful BST search among n points. */
export function averagePathLength(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * (Math.log(n - 1) + EULER_GAMMA) - (2 * (n - 1)) / n;
}

/** Small, fast, seedable PRNG (mulberry32). Returns floats in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function round4(n: number): number {
  return Math.round(n * 10_000) / 10_000;
}

function buildTree(
  rows: readonly (readonly number[])[],
  depth: number,
  limit: number,
  rand: () => number,
  out: EncodedTree,
): void {
  if (depth >= limit || rows.length <= 1) {
    out.push(-Math.max(1, rows.length));
    return;
  }
  const dims = rows[0]!.length;
  // Only features that still vary within this node can split it.
  const candidates: { f: number; min: number; max: number }[] = [];
  for (let f = 0; f < dims; f++) {
    let min = Infinity;
    let max = -Infinity;
    for (const r of rows) {
      const v = r[f]!;
      if (v < min) min = v;
      if (v > max) max = v;
    }
    if (max > min) candidates.push({ f, min, max });
  }
  if (candidates.length === 0) {
    out.push(-rows.length);
    return;
  }
  const { f, min, max } = candidates[Math.floor(rand() * candidates.length)]!;
  let threshold = round4(min + rand() * (max - min));
  // Rounding must not collapse the split onto an edge.
  if (threshold <= min || threshold >= max) threshold = (min + max) / 2;
  const left = rows.filter((r) => r[f]! < threshold);
  const right = rows.filter((r) => r[f]! >= threshold);
  out.push(f, threshold, 0);
  const lengthSlot = out.length - 1;
  const leftStart = out.length;
  buildTree(left, depth + 1, limit, rand, out);
  out[lengthSlot] = out.length - leftStart;
  buildTree(right, depth + 1, limit, rand, out);
}

/** Trains a forest on rows of equal length. Same data + seed ⇒ same model. */
export function fitForest(data: readonly (readonly number[])[], opts: FitOptions): ForestModel {
  if (data.length < 2) throw new Error('Isolation Forest needs at least 2 training rows.');
  const sampleSize = Math.min(opts.sampleSize, data.length);
  const limit = Math.ceil(Math.log2(sampleSize));
  const rand = mulberry32(opts.seed);
  const trees: EncodedTree[] = [];
  for (let t = 0; t < opts.trees; t++) {
    // Sample without replacement (partial Fisher–Yates over indices).
    const idx = data.map((_, i) => i);
    for (let i = 0; i < sampleSize; i++) {
      const j = i + Math.floor(rand() * (idx.length - i));
      [idx[i], idx[j]] = [idx[j]!, idx[i]!];
    }
    const sample = idx.slice(0, sampleSize).map((i) => data[i]!);
    const encoded: EncodedTree = [];
    buildTree(sample, 0, limit, rand, encoded);
    trees.push(encoded);
  }
  return { sampleSize, trees };
}

/** Path length of `x` in one encoded tree, including the c(size) leaf adjustment. */
export function pathLength(tree: EncodedTree, x: readonly number[]): number {
  let pos = 0;
  let depth = 0;
  for (;;) {
    const head = tree[pos]!;
    if (head < 0) return depth + averagePathLength(-head);
    const threshold = tree[pos + 1]!;
    const leftLength = tree[pos + 2]!;
    pos = x[head]! < threshold ? pos + 3 : pos + 3 + leftLength;
    depth++;
  }
}

/** Anomaly score in (0, 1]; higher is more anomalous. */
export function anomalyScore(model: ForestModel, x: readonly number[]): number {
  const mean = model.trees.reduce((sum, t) => sum + pathLength(t, x), 0) / model.trees.length;
  return 2 ** (-mean / averagePathLength(model.sampleSize));
}
