import { describe, expect, it, vi } from 'vitest';
import { cacheKey, TtlCache } from '../src/server/cache.js';
import { loadConfig } from '../src/server/config.js';
import { rateLimiter } from '../src/server/security.js';
import {
  auditEntry,
  buildRunbook,
  countLines,
  currentDecisions,
  formatTime,
  orderedIncidents,
} from '../src/shared/report.js';
import type { AnalysisResult } from '../src/shared/types.js';
import { AnalysisService } from '../src/server/service.js';
import { sample, testConfig } from './helpers.js';

describe('TtlCache', () => {
  it('expires entries and evicts the least recently used', () => {
    let now = 0;
    const cache = new TtlCache<number>(2, 100, () => now);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.get('a')).toBe(1); // a is now most recent
    cache.set('c', 3);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.size).toBe(2);
    now = 500;
    expect(cache.get('a')).toBeUndefined();
  });

  it('hashes key parts unambiguously', () => {
    expect(cacheKey('ab', 'c')).not.toBe(cacheKey('a', 'bc'));
  });
});

describe('loadConfig', () => {
  it('uses safe defaults and ignores invalid numbers', () => {
    const c = loadConfig({ PORT: 'abc', GEMINI_API_KEY: '  ' });
    expect(c.port).toBe(8080);
    expect(c.geminiApiKey).toBeUndefined();
    expect(c.models).toEqual(['gemini-3.1-flash-lite', 'gemini-3.5-flash']);
  });

  it('reads overrides and dedupes models', () => {
    const c = loadConfig({
      PORT: '9000',
      GEMINI_API_KEY: 'k',
      GEMINI_MODEL: 'm',
      GEMINI_FALLBACK_MODEL: 'm',
    });
    expect(c).toMatchObject({ port: 9000, geminiApiKey: 'k', models: ['m'] });
  });
});

describe('rateLimiter', () => {
  it('opens a new window after a minute', () => {
    let now = 0;
    const limiter = rateLimiter(1, () => now);
    const res = { setHeader: vi.fn(), status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();
    const req = { ip: '1.1.1.1' };
    limiter(req as never, res as never, next);
    limiter(req as never, res as never, next);
    expect(res.status).toHaveBeenCalledWith(429);
    now = 61_000;
    limiter(req as never, res as never, next);
    expect(next).toHaveBeenCalledTimes(2);
  });
});

describe('report helpers', () => {
  async function result(): Promise<AnalysisResult> {
    const service = new AnalysisService(testConfig(), undefined);
    return service.analyze({ logs: sample('kill-chain'), useAi: false, requestId: 'req-1' });
  }

  it('orders incidents by priority and formats time', async () => {
    const r = await result();
    expect(orderedIncidents(r).map((i) => i.id)).toEqual(['INC-1', 'INC-2']);
    expect(formatTime(Date.UTC(2026, 10, 18, 2, 3, 4))).toBe('2026-11-18 02:03:04 UTC');
    expect(formatTime(null)).toBe('unknown time');
  });

  it('keeps the latest decision per action and sanitises analyst names', () => {
    const audit = [
      auditEntry('ACT-1', 'approved', ''),
      auditEntry('ACT-1', 'rejected', 'Ana\nLyst'),
    ];
    expect(currentDecisions(audit).get('ACT-1')).toBe('rejected');
    expect(audit[0]!.analyst).toBe('unnamed analyst');
    expect(audit[1]!.analyst).toBe('Ana Lyst');
  });

  it('builds a runbook with only approved actions and the audit trail', async () => {
    const r = await result();
    const audit = [
      auditEntry('ACT-1', 'approved', 'Priya', new Date('2026-11-18T10:00:00Z')),
      auditEntry('ACT-2', 'rejected', 'Priya|x', new Date('2026-11-18T10:01:00Z')),
    ];
    const md = buildRunbook(r, audit);
    expect(md).toContain('## Approved actions');
    expect(md).toContain(r.actions[0]!.command);
    expect(md).not.toContain(r.actions[1]!.command);
    expect(md).toContain('| 2026-11-18T10:01:00.000Z |');
    expect(md).toContain('Priya/x');
    expect(buildRunbook(r, [])).toContain('_No actions approved yet._');
  });

  it('counts non-empty lines', () => {
    expect(countLines('a\n\n b \r\n')).toBe(2);
  });
});
