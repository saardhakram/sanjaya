import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/server/app.js';
import { AnalysisService } from '../src/server/service.js';
import { callResponse, engine, FakeModel, sample, testConfig, validSubmission } from './helpers.js';

const publicDir = mkdtempSync(path.join(tmpdir(), 'sd-public-'));
writeFileSync(path.join(publicDir, 'index.html'), '<!doctype html><title>Sanjaya</title>');
writeFileSync(path.join(publicDir, '.secret'), 'nope');

function makeApp(client?: FakeModel, overrides = {}) {
  const config = testConfig(overrides);
  return createApp({ config, service: new AnalysisService(config, client), publicDir });
}

describe('HTTP basics', () => {
  it('serves health, status and the static app with security headers', async () => {
    const app = makeApp();
    await request(app).get('/healthz').expect(200, { status: 'ok' });
    const status = await request(app).get('/api/status').expect(200);
    expect(status.body).toMatchObject({ aiAvailable: false, model: null });
    const page = await request(app).get('/').expect(200);
    expect(page.headers['content-security-policy']).toContain("script-src 'self'");
    expect(page.headers['content-security-policy']).not.toContain('unsafe-inline');
    expect(page.headers['x-content-type-options']).toBe('nosniff');
    expect(page.headers['strict-transport-security']).toContain('max-age');
    expect(page.headers['permissions-policy']).toContain('camera=()');
    expect(page.headers['x-request-id']).toMatch(/[0-9a-f-]{36}/);
    expect(page.headers['x-powered-by']).toBeUndefined();
  });

  it('does not serve dotfiles or traverse outside the public dir', async () => {
    const app = makeApp();
    const dot = await request(app).get('/.secret');
    expect([403, 404]).toContain(dot.status);
    expect(dot.text).not.toContain('nope');
    const res = await request(app).get('/..%2f..%2fetc%2fpasswd');
    expect([400, 403, 404]).toContain(res.status);
  });

  it('returns JSON 404 for unknown API routes', async () => {
    await request(makeApp()).get('/api/nope').expect(404, { error: 'Not found.' });
  });
});

describe('POST /api/analyze', () => {
  it('analyzes with rules when AI is not configured', async () => {
    const res = await request(makeApp())
      .post('/api/analyze')
      .send({ logs: sample('kill-chain') })
      .expect(200);
    expect(res.body.stats.incidents).toBe(2);
    expect(res.body.meta).toMatchObject({
      engine: 'rules',
      fallbackReason: 'Gemini is not configured on this server.',
    });
    expect(res.body.actions.length).toBeGreaterThan(5);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('uses the Gemini agent and caches identical requests', async () => {
    const state = engine('kill-chain');
    const model = new FakeModel([
      callResponse([{ name: 'submit_triage', args: validSubmission(state) }]),
    ]);
    const app = makeApp(model);
    const first = await request(app)
      .post('/api/analyze')
      .send({ logs: sample('kill-chain') })
      .expect(200);
    expect(first.body.meta).toMatchObject({
      engine: 'gemini',
      model: 'gemini-3.1-flash-lite',
      cached: false,
    });
    expect(first.body.triage.executiveSummary).toMatch(/brute-forced SSH/);
    const second = await request(app)
      .post('/api/analyze')
      .send({ logs: sample('kill-chain') })
      .expect(200);
    expect(second.body.meta.cached).toBe(true);
    expect(second.body.meta.requestId).not.toBe(first.body.meta.requestId);
    expect(model.requests).toHaveLength(1);
  });

  it('falls back to rules when the agent fails, and does not cache the failure', async () => {
    const model = new FakeModel([new Error('quota')]);
    const app = makeApp(model);
    const res = await request(app)
      .post('/api/analyze')
      .send({ logs: sample('ssh-compromise') })
      .expect(200);
    expect(res.body.meta.engine).toBe('rules');
    expect(res.body.meta.fallbackReason).toMatch(/unavailable/);
    await request(app)
      .post('/api/analyze')
      .send({ logs: sample('ssh-compromise') })
      .expect(200);
    expect(model.requests.length).toBeGreaterThan(2);
  });

  it('skips the agent when the user turns AI off or there is nothing to investigate', async () => {
    const model = new FakeModel([new Error('should not be called')]);
    const app = makeApp(model);
    const off = await request(app)
      .post('/api/analyze')
      .send({ logs: sample('kill-chain'), useAi: false })
      .expect(200);
    expect(off.body.meta.fallbackReason).toMatch(/turned off/);
    const clean = await request(app)
      .post('/api/analyze')
      .send({ logs: sample('clean') })
      .expect(200);
    expect(clean.body.meta.fallbackReason).toMatch(/No incidents/);
    expect(model.requests).toHaveLength(0);
  });

  it('validates input', async () => {
    const app = makeApp();
    const empty = await request(app).post('/api/analyze').send({ logs: '' }).expect(400);
    expect(empty.body.error).toMatch(/Paste or upload/);
    await request(app).post('/api/analyze').send({ logs: 42 }).expect(400);
    await request(app).post('/api/analyze').send({ logs: 'x', useAi: 'yes' }).expect(400);
    const tooManyLines = await request(makeApp(undefined, { maxLines: 3 }))
      .post('/api/analyze')
      .send({ logs: 'a\nb\nc\nd' })
      .expect(400);
    expect(tooManyLines.body.error).toMatch(/at most 3 lines/);
  });

  it('rejects oversized payloads and malformed JSON with generic errors', async () => {
    const app = makeApp(undefined, { maxLogBytes: 1024 });
    const big = await request(app)
      .post('/api/analyze')
      .send({ logs: 'x'.repeat(40_000) })
      .expect(413);
    expect(big.body.error).toBe('Upload too large.');
    const tooBigForSchema = await request(app)
      .post('/api/analyze')
      .send({ logs: 'x'.repeat(2000) })
      .expect(400);
    expect(tooBigForSchema.body.error).toMatch(/under 1 KB/);
    const bad = await request(app)
      .post('/api/analyze')
      .set('Content-Type', 'application/json')
      .send('{"logs":')
      .expect(400);
    expect(bad.body.error).toBe('Malformed request body.');
  });

  it('blocks cross-origin browser requests', async () => {
    const app = makeApp();
    await request(app)
      .post('/api/analyze')
      .set('Origin', 'https://evil.example')
      .send({ logs: 'x' })
      .expect(403);
    await request(app)
      .post('/api/analyze')
      .set('Origin', 'not a url')
      .send({ logs: 'x' })
      .expect(403);
  });

  it('rate-limits each client', async () => {
    const app = makeApp(undefined, { rateLimitPerMinute: 2 });
    await request(app).get('/api/status').expect(200);
    await request(app).get('/api/status').expect(200);
    const limited = await request(app).get('/api/status').expect(429);
    expect(limited.headers['retry-after']).toBeDefined();
  });
});
