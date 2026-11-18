// End-to-end smoke test against a running deployment.
// Usage: node scripts/smoke.mjs https://your-service.run.app
const base = (process.argv[2] ?? 'http://localhost:8080').replace(/\/$/, '');

const SAMPLE = [
  ...Array.from(
    { length: 8 },
    (_, i) =>
      `Nov 18 02:0${i}:00 web-01 sshd[1]: Failed password for root from 203.0.113.45 port ${5000 + i} ssh2`,
  ),
  'Nov 18 02:09:00 web-01 sshd[2]: Accepted password for root from 203.0.113.45 port 6000 ssh2',
].join('\n');

let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

await check('GET /healthz', async () => {
  const r = await fetch(`${base}/healthz`);
  assert(r.ok, `status ${r.status}`);
});
await check('GET / serves the app with a strict CSP', async () => {
  const r = await fetch(base);
  assert(r.ok, `status ${r.status}`);
  assert(
    (r.headers.get('content-security-policy') ?? '').includes("script-src 'self'"),
    'CSP missing',
  );
});
await check('GET /api/status', async () => {
  const r = await fetch(`${base}/api/status`);
  const body = await r.json();
  console.log(`     aiAvailable=${body.aiAvailable} model=${body.model}`);
});
await check('POST /api/analyze detects the compromise', async () => {
  const r = await fetch(`${base}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs: SAMPLE, useAi: true }),
  });
  const body = await r.json();
  assert(r.ok, `status ${r.status}: ${JSON.stringify(body)}`);
  assert(body.incidents[0]?.severity === 'critical', 'expected a critical incident');
  console.log(
    `     engine=${body.meta.engine} model=${body.meta.model ?? '-'} turns=${body.meta.agentTurns} ` +
      `tokens=${body.meta.tokens.input + body.meta.tokens.output} ${body.meta.fallbackReason ?? ''}`,
  );
});
await check('POST /api/analyze rejects empty input', async () => {
  const r = await fetch(`${base}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs: '' }),
  });
  assert(r.status === 400, `status ${r.status}`);
});

process.exit(failed ? 1 : 0);
