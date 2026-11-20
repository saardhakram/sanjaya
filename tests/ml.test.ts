import { describe, expect, it } from 'vitest';
import { parseLogs } from '../src/server/engine/parsers.js';
import { runDetectors } from '../src/server/engine/detectors.js';
import { benignProfiles } from '../src/server/ml/baseline.js';
import { DRISHTI, runDrishti } from '../src/server/ml/drishti.js';
import {
  FEATURES,
  groupIndices,
  oddCharShare,
  profileFor,
  profilesFrom,
  RATIO_PRIOR,
} from '../src/server/ml/features.js';
import {
  anomalyScore,
  averagePathLength,
  fitForest,
  mulberry32,
  pathLength,
} from '../src/server/ml/iforest.js';
import {
  DRISHTI_MODEL,
  excess,
  explain,
  formatValue,
  judge,
  percentileRank,
} from '../src/server/ml/model.js';
import { trainDrishti } from '../src/server/ml/train.js';
import type { LogEvent } from '../src/shared/types.js';
import { engine, sample } from './helpers.js';

const events = (logs: string): LogEvent[] => parseLogs(logs, { referenceYear: 2026 }).events;

describe('Isolation Forest', () => {
  it('uses the standard average path length c(n)', () => {
    expect(averagePathLength(1)).toBe(0);
    expect(averagePathLength(2)).toBe(1);
    expect(averagePathLength(256)).toBeCloseTo(10.24, 1);
  });

  it('has a seeded PRNG that is repeatable and stays in [0, 1)', () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    const xs = Array.from({ length: 1000 }, () => a());
    expect(xs).toEqual(Array.from({ length: 1000 }, () => b()));
    expect(Math.min(...xs)).toBeGreaterThanOrEqual(0);
    expect(Math.max(...xs)).toBeLessThan(1);
  });

  it('isolates an outlier faster than points in the crowd', () => {
    const rand = mulberry32(1);
    const crowd = Array.from({ length: 300 }, () => [rand(), rand()]);
    const model = fitForest(crowd, { trees: 60, sampleSize: 128, seed: 3 });
    const inlier = anomalyScore(model, [0.5, 0.5]);
    const outlier = anomalyScore(model, [4, -3]);
    expect(outlier).toBeGreaterThan(0.6);
    expect(inlier).toBeLessThan(0.5);
  });

  it('is deterministic for the same data and seed', () => {
    const rows = [
      [1, 2],
      [2, 3],
      [3, 1],
      [9, 9],
    ];
    expect(fitForest(rows, { trees: 5, sampleSize: 4, seed: 7 })).toEqual(
      fitForest(rows, { trees: 5, sampleSize: 4, seed: 7 }),
    );
  });

  it('handles identical rows and rejects tiny training sets', () => {
    const same = fitForest(
      [
        [1, 1],
        [1, 1],
        [1, 1],
      ],
      { trees: 2, sampleSize: 8, seed: 1 },
    );
    expect(same.trees[0]).toEqual([-3]); // nothing varies, so the root is a leaf
    expect(pathLength(same.trees[0]!, [5, 5])).toBeCloseTo(averagePathLength(3));
    expect(() => fitForest([[1]], { trees: 1, sampleSize: 1, seed: 1 })).toThrow(/at least 2/);
  });

  it('walks the compact encoding: [feature, threshold, leftLength, ...left, ...right]', () => {
    const tree = [0, 5, 1, -2, -1]; // x0 < 5 → leaf of 2, else leaf of 1
    expect(pathLength(tree, [1])).toBeCloseTo(1 + averagePathLength(2));
    expect(pathLength(tree, [9])).toBeCloseTo(1 + averagePathLength(1));
  });
});

describe('behaviour features', () => {
  it('counts code-like characters, including leftover %XX from double encoding', () => {
    expect(oddCharShare('')).toBe(0);
    expect(oddCharShare('/products?id=12')).toBe(0);
    expect(oddCharShare('/?x=${jndi:ldap://x/a}')).toBeGreaterThan(0.15);
    expect(oddCharShare('/a%2e%2e/b')).toBeCloseTo(0.4);
    expect(oddCharShare('\'"<>;|`$(){}')).toBe(1);
  });

  it('profiles an IP and smooths shares from tiny samples', () => {
    const p = profileFor('192.0.2.9', [
      {
        line: 1,
        raw: '',
        source: 'web',
        kind: 'http_request',
        timestamp: 0,
        srcIp: '192.0.2.9',
        path: '/x',
        status: 404,
        userAgent: 'curl/8',
      },
    ]);
    const i4xx = FEATURES.findIndex((f) => f.key === 'http4xxRatio');
    expect(p.groups).toEqual(['web']);
    expect(p.raw[i4xx]).toBe(1); // what people see: 1 of 1 request failed
    expect(p.vector[i4xx]).toBeCloseTo(1 / (1 + RATIO_PRIOR)); // what the model sees
    expect(p.vector[FEATURES.findIndex((f) => f.key === 'requests')]).toBeCloseTo(Math.log1p(1));
  });

  it('builds one profile per source IP and tags its traffic groups', () => {
    const profiles = profilesFrom(events(sample('kill-chain')));
    const attacker = profiles.find((p) => p.ip === '203.0.113.45')!;
    expect(attacker.groups).toEqual(['auth', 'network']);
    expect(groupIndices('network').map((i) => FEATURES[i]!.key)).toEqual([
      'firewallEvents',
      'firewallBlockRatio',
      'distinctPorts',
    ]);
  });
});

describe('Drishti model', () => {
  it('ranks values against stored percentiles', () => {
    const pct = Array.from({ length: 101 }, (_, i) => i);
    expect(percentileRank(pct, -1)).toBe(0);
    expect(percentileRank(pct, 100)).toBe(1);
    expect(percentileRank(pct, 50.5)).toBeCloseTo(0.505);
    expect(percentileRank([0, 0, 0, 1], 0)).toBeCloseTo(2 / 3); // flat runs resolve upwards
    expect(excess(pct, 99)).toBe(0);
  });

  it('formats values for people', () => {
    expect(
      formatValue(
        FEATURES.find((f) => f.scale === 'ratio')!,
        0.934,
      ),
    ).toBe('93%');
    expect(
      formatValue(
        FEATURES.find((f) => f.scale === 'chars')!,
        37.4,
      ),
    ).toBe('37 chars');
    expect(
      formatValue(
        FEATURES.find((f) => f.scale === 'count')!,
        14,
      ),
    ).toBe('14');
  });

  it('returns no verdict for an IP with no judged traffic', () => {
    expect(
      judge(new Array(FEATURES.length).fill(0), new Array(FEATURES.length).fill(0), []),
    ).toBeNull();
    expect(explain(DRISHTI_MODEL, new Array(FEATURES.length).fill(0), [], [])).toEqual([]);
  });

  it('is exactly reproducible from the training script', () => {
    const { model, report } = trainDrishti();
    expect(model).toEqual(DRISHTI_MODEL);
    for (const g of report) expect(g.falsePositiveRate).toBeLessThanOrEqual(0.002);
  }, 30_000);

  it('rarely flags benign clients it has never seen (held-out traffic)', () => {
    const holdout = benignProfiles(1500, 7);
    const flagged = holdout.filter((p) => judge(p.vector, p.raw, p.groups)!.anomalous);
    expect(flagged.length / holdout.length).toBeLessThan(0.005);
  });
});

describe('runDrishti', () => {
  it('catches low-and-slow attacks that every rule misses', () => {
    const evts = events(sample('stealth'));
    const rules = runDetectors(evts);
    expect(rules).toEqual([]);
    const { report, findings } = runDrishti(evts, rules);
    expect(findings.map((f) => f.ip).sort()).toEqual([
      '192.0.2.200',
      '198.51.100.88',
      '203.0.113.66',
    ]);
    expect(report.newFindings).toBe(3);
    expect(report.entities[0]!.score).toBeGreaterThanOrEqual(report.entities[1]!.score);

    const slow = findings.find((f) => f.ip === '203.0.113.66')!;
    expect(slow.detector).toBe('ml_anomaly');
    expect(slow.user).toBe('deploy');
    expect(slow.techniques).toEqual(['T1110.001', 'T1078']);
    expect(slow.details).toMatch(/no rule matched it/);
    expect(slow.details).toMatch(/logged in successfully as "deploy"/);
    expect(slow.score).toBeLessThanOrEqual(DRISHTI.maxFindingScore);

    expect(findings.find((f) => f.ip === '198.51.100.88')!.techniques).toEqual(['T1119']);
    expect(findings.find((f) => f.ip === '192.0.2.200')!.techniques).toEqual(['T1190']);
  });

  it('stays quiet on a normal day', () => {
    const { report, findings } = runDrishti(events(sample('clean')), []);
    expect(report.flagged).toBe(0);
    expect(findings).toEqual([]);
  });

  it('agrees with the rules on loud attacks without duplicating their findings', () => {
    const evts = events(sample('kill-chain'));
    const rules = runDetectors(evts);
    const { report, findings } = runDrishti(evts, rules);
    const attacker = report.entities.find((e) => e.ip === '203.0.113.45')!;
    expect(attacker).toMatchObject({ anomalous: true, ruleFlagged: true });
    expect(attacker.reasons.map((r) => r.feature)).toContain('distinctPorts');
    expect(findings).toEqual([]);
  });

  it('does not judge an IP on fewer than the minimum number of events', () => {
    const { report } = runDrishti(events(sample('web-attack')), []);
    const single = report.entities.find((e) => e.ip === '203.0.113.99')!;
    expect(single.events).toBeLessThan(DRISHTI.minEvents);
    expect(single.anomalous).toBe(false);
  });

  it('flows into the engine: findings, incidents and the report', () => {
    const state = engine('stealth');
    expect(state.findings.map((f) => f.id)).toEqual(['F-001', 'F-002', 'F-003']);
    expect(state.incidents).toHaveLength(3);
    expect(state.drishti.flagged).toBe(3);
    const login = state.incidents.find((i) => i.users.includes('deploy'))!;
    expect(login.baselineActions.map((a) => a.action)).toEqual([
      'escalate_to_human',
      'preserve_evidence',
      'terminate_sessions',
      'force_password_reset',
      'block_ip',
    ]);
  });
});
