// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { chakra, renderDecisions, renderResults, type Handlers } from '../src/client/render.js';
import { AnalysisService } from '../src/server/service.js';
import { auditEntry } from '../src/shared/report.js';
import type { AnalysisResult } from '../src/shared/types.js';
import { sample, testConfig } from './helpers.js';

const XSS_LINE =
  '203.0.113.66 - - [18/Nov/2026:09:00:00 +0000] "GET /q?s=<svg/onload=alert(1)><img/src/onerror=alert(2)> HTTP/1.1" 200 10 "-" "ua"';

async function analyse(logs: string): Promise<AnalysisResult> {
  return new AnalysisService(testConfig(), undefined).analyze({
    logs,
    useAi: false,
    requestId: 'r1',
  });
}

function handlers(): Handlers & Record<string, ReturnType<typeof vi.fn>> {
  return {
    onDecide: vi.fn(),
    onExportRunbook: vi.fn(),
    onExportJson: vi.fn(),
    onAnalystChange: vi.fn(),
  };
}

let root: HTMLElement;
beforeEach(() => {
  document.body.innerHTML = '<div id="root"></div>';
  root = document.getElementById('root')!;
});

describe('renderResults', () => {
  it('renders the report with the Sanjaya narration, incidents and the Chakravyuha', async () => {
    const result = await analyse(sample('kill-chain'));
    renderResults(root, result, sample('kill-chain'), '', handlers());

    expect(root.querySelector('#report-heading')?.textContent).toBe('What Sanjaya saw');
    const uvacha = root.querySelector('.uvacha')!;
    expect(uvacha.textContent).toBe('सञ्जय उवाच');
    expect(uvacha.getAttribute('lang')).toBe('sa');
    expect(root.querySelectorAll('.incident')).toHaveLength(result.incidents.length);
    expect(root.querySelector('.meta')?.textContent).toMatch(/^Read by the rule engine in/);

    // Each stage of the Chakravyuha is drawn one ring deeper (capped at 5).
    const stages = [...root.querySelectorAll('.incident')[0]!.querySelectorAll('.chain li')];
    expect(stages.length).toBeGreaterThanOrEqual(5);
    expect(stages.map((li) => li.querySelectorAll('circle').length).slice(0, 5)).toEqual([
      1, 2, 3, 4, 5,
    ]);
    expect(root.querySelector('.ledger h3')?.textContent).toBe('Chitragupta’s ledger');
  });

  it('shows attacker-controlled log text as text, never as markup', async () => {
    const result = await analyse(XSS_LINE);
    expect(result.findings.length).toBeGreaterThan(0);
    renderResults(root, result, XSS_LINE, '', handlers());
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelector('.evidence svg')).toBeNull();
    expect(root.querySelector('.evidence')?.textContent).toContain(
      '<svg/onload=alert(1)><img/src/onerror=alert(2)>',
    );
  });

  it('describes Gemini and cached runs in the meta line', async () => {
    const base = await analyse(sample('ssh-compromise'));
    const gemini: AnalysisResult = {
      ...base,
      meta: {
        ...base.meta,
        engine: 'gemini',
        model: 'gemini-x',
        agentTurns: 1,
        toolCalls: 3,
        tokens: { input: 900, output: 100 },
        durationMs: 2500,
      },
      triage: { ...base.triage, analystNotes: 'A planted instruction was ignored.' },
    };
    renderResults(root, gemini, sample('ssh-compromise'), '', handlers());
    expect(root.querySelector('.meta')?.textContent).toBe(
      'Investigated by gemini-x in 2.5 s: 1 turn, 3 tool calls, 1,000 tokens.',
    );
    expect(root.querySelector('.ai-badge')?.textContent).toBe('Gemini analyst');
    expect(root.textContent).toContain('A planted instruction was ignored.');

    renderResults(root, { ...gemini, meta: { ...gemini.meta, cached: true } }, '', '', handlers());
    expect(root.querySelector('.meta')?.textContent).toMatch(/^Served from memory/);
  });

  it('shows Drishti, the ML third eye, with a score bar and reasons per IP', async () => {
    const result = await analyse(sample('stealth'));
    renderResults(root, result, sample('stealth'), '', handlers());
    const card = root.querySelector('.drishti')!;
    expect(card.querySelector('.drishti-deva')?.textContent).toBe('दृष्टि');
    expect(card.classList.contains('has-missed')).toBe(true);
    expect(card.querySelector('.drishti-summary')?.textContent).toMatch(
      /3 of them slipped past every rule/,
    );
    const missed = card.querySelectorAll('.d-row.missed');
    expect(missed).toHaveLength(3);
    const first = missed[0] as HTMLElement;
    expect(first.querySelector<HTMLElement>('.d-fill')!.style.width).toBe('100%');
    expect(first.querySelector('.d-bar')?.getAttribute('aria-label')).toBe(
      'Anomaly score 100 of 100',
    );
    expect(first.querySelectorAll('.d-reasons li').length).toBeGreaterThan(0);
    expect(card.querySelectorAll('.d-tag.normal').length).toBeGreaterThan(0);
    expect(root.querySelectorAll('.ml-tag').length).toBe(3);
  });

  it('lists only the top IPs and says when the rules caught everything', () => {
    const entity = (i: number, anomalous: boolean) => ({
      ip: `192.0.2.${i}`,
      score: anomalous ? 80 : 10,
      anomalous,
      ruleFlagged: true,
      events: 5,
      groups: ['web' as const],
      reasons: [],
    });
    const base = {
      stats: {
        linesTotal: 1,
        linesParsed: 1,
        bySource: { auth: 0, web: 1, firewall: 0, unknown: 0 },
        findings: 0,
        incidents: 0,
        critical: 0,
        high: 0,
      },
      findings: [],
      incidents: [],
      actions: [],
      triage: { executiveSummary: 'x', assessments: [], analystNotes: '' },
      meta: {
        engine: 'rules' as const,
        tokens: { input: 0, output: 0 },
        agentTurns: 0,
        toolCalls: 0,
        cached: false,
        durationMs: 1,
        requestId: 'r',
      },
    };
    const result: AnalysisResult = {
      ...base,
      drishti: {
        model: 'm',
        trainingProfiles: 10,
        trees: 3,
        flagged: 1,
        newFindings: 0,
        entities: [entity(1, true), ...Array.from({ length: 9 }, (_, i) => entity(i + 2, false))],
      },
    };
    renderResults(root, result, '', '', handlers());
    expect(root.querySelectorAll('.d-row')).toHaveLength(8);
    expect(root.querySelector('.drishti-summary')?.textContent).toMatch(
      /rules caught all of them too/,
    );
    expect(root.querySelector('.d-row .d-tag')?.textContent).toBe('Rules agree');
    expect(root.querySelector('.drishti')?.textContent).toMatch(/2 more IP\(s\) scored lower/);
  });

  it('renders a quiet day without incidents or a ledger', async () => {
    const result = await analyse(sample('clean'));
    renderResults(root, result, sample('clean'), '', handlers());
    expect(root.querySelector('.narration')?.classList.contains('clean')).toBe(true);
    expect(root.querySelector('.incident')).toBeNull();
    expect(root.querySelector('.ledger')).toBeNull();
    expect(root.querySelector('.drishti-summary')?.textContent).toMatch(
      /behaves like normal traffic/,
    );
  });
});

describe('approvals', () => {
  it('approves low-risk actions in one click and asks to confirm high-risk ones', async () => {
    const result = await analyse(sample('ssh-compromise'));
    const hd = handlers();
    renderResults(root, result, sample('ssh-compromise'), 'Asha', hd);

    const low = result.actions.find((a) => a.risk === 'low')!;
    const high = result.actions.find((a) => a.risk === 'high')!;
    const btn = (id: string, role: string) =>
      root.querySelector<HTMLButtonElement>(`[data-action-id="${id}"] [data-role=${role}]`)!;

    btn(low.id, 'approve').click();
    expect(hd.onDecide).toHaveBeenLastCalledWith(low, 'approved');

    btn(high.id, 'approve').click();
    expect(btn(high.id, 'approve').textContent).toBe('Confirm: this cannot be undone');
    expect(hd.onDecide).toHaveBeenCalledTimes(1);
    btn(high.id, 'reject').click();
    expect(btn(high.id, 'approve').textContent).toBe('Approve');
    expect(hd.onDecide).toHaveBeenLastCalledWith(high, 'rejected');
    btn(high.id, 'approve').click();
    btn(high.id, 'approve').click();
    expect(hd.onDecide).toHaveBeenLastCalledWith(high, 'approved');
  });

  it('reflects decisions and the ledger in place', async () => {
    const result = await analyse(sample('ssh-compromise'));
    renderResults(root, result, sample('ssh-compromise'), '', handlers());
    const [a, b] = result.actions;
    renderDecisions(root, result, [
      auditEntry(a!.id, 'approved', 'Asha'),
      auditEntry(b!.id, 'rejected', 'Asha'),
    ]);

    const itemA = root.querySelector(`[data-action-id="${a!.id}"]`)!;
    expect(itemA.classList.contains('is-approved')).toBe(true);
    expect(itemA.querySelector('[data-role=approve]')?.getAttribute('aria-pressed')).toBe('true');
    expect(itemA.querySelector('[data-role=state]')?.textContent).toBe('Approved');
    expect(root.querySelector(`[data-action-id="${b!.id}"] [data-role=state]`)?.textContent).toBe(
      'Rejected',
    );
    expect(root.querySelector('#approved-count')?.textContent).toBe(
      `1 of ${result.actions.length} actions approved`,
    );
    const entries = [...root.querySelectorAll('#audit li')].map((li) => li.textContent);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toContain(`Asha rejected ${b!.id}`);
  });

  it('wires the ledger controls to their handlers', async () => {
    const result = await analyse(sample('ssh-compromise'));
    const hd = handlers();
    renderResults(root, result, sample('ssh-compromise'), '', hd);
    const input = root.querySelector<HTMLInputElement>('#analyst')!;
    input.value = 'Ravi';
    input.dispatchEvent(new Event('input'));
    expect(hd.onAnalystChange).toHaveBeenCalledWith('Ravi');
    const [md, json] = [...root.querySelectorAll<HTMLButtonElement>('.ledger .btn')];
    md!.click();
    json!.click();
    expect(hd.onExportRunbook).toHaveBeenCalledOnce();
    expect(hd.onExportJson).toHaveBeenCalledOnce();
  });
});

describe('chakra emblem', () => {
  it('references the shared symbol and is hidden from assistive technology', () => {
    const svg = chakra();
    expect(svg.getAttribute('aria-hidden')).toBe('true');
    expect(svg.querySelector('use')?.getAttribute('href')).toBe('#chakra');
  });
});
