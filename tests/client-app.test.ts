// @vitest-environment jsdom
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { byId, download, h } from '../src/client/dom.js';
import { AnalysisService } from '../src/server/service.js';
import { testConfig } from './helpers.js';

const BODY = /<body>([\s\S]*)<\/body>/.exec(readFileSync('public/index.html', 'utf8'))![1]!;

type Route = (body: unknown) => { status: number; json: unknown };

/** Boots the real client (main.ts) against index.html with a fake API. */
async function boot(routes: { status?: Route; analyze?: Route } = {}) {
  document.body.innerHTML = BODY;
  const service = new AnalysisService(testConfig(), undefined);
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    let res: { status: number; json: unknown };
    if (url === '/api/status') {
      res = routes.status?.(body) ?? {
        status: 200,
        json: { aiAvailable: true, model: 'gemini-test' },
      };
    } else {
      const req = body as { logs: string; useAi: boolean };
      res = routes.analyze?.(body) ?? {
        status: 200,
        json: await service.analyze({ logs: req.logs, useAi: false, requestId: 'r' }),
      };
    }
    return new Response(JSON.stringify(res.json), { status: res.status });
  });
  vi.stubGlobal('fetch', fetchMock);
  vi.resetModules();
  await import('../src/client/main.js');
  await vi.waitFor(() => expect(byId('ai-status').textContent).not.toMatch(/Checking/));
  return fetchMock;
}

const submit = () => byId<HTMLFormElement>('analyze-form').requestSubmit();

const createObjectURL = vi.fn(() => 'blob:x');
beforeEach(() => {
  createObjectURL.mockClear();
  URL.createObjectURL = createObjectURL;
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('client app', () => {
  it('shows the AI status, loads a demo battle and renders the report', async () => {
    const fetchMock = await boot();
    expect(byId('ai-status').textContent).toBe('Gemini analyst ready (gemini-test)');
    expect(byId('ai-status').classList.contains('online')).toBe(true);

    const demo = document.querySelector<HTMLButtonElement>('[data-sample="kill-chain"]')!;
    demo.click();
    expect(demo.getAttribute('aria-pressed')).toBe('true');
    expect(byId('log-count').textContent).toBe('55 lines');

    submit();
    expect(byId('analyze-btn').textContent).toBe('Sanjaya is looking…');
    expect(document.querySelector('.loading svg use')).not.toBeNull();
    await vi.waitFor(() => expect(document.querySelector('#report-heading')).not.toBeNull());
    expect(document.activeElement?.id).toBe('report-heading');
    expect(byId('status').textContent).toMatch(/^Analysis complete: 2 incident/);
    expect(byId('analyze-btn').textContent).toBe('Analyze logs');
    const sent = fetchMock.mock.calls.at(-1)![1]!.body;
    expect(typeof sent === 'string' ? JSON.parse(sent) : null).toMatchObject({ useAi: true });
  });

  it('records decisions and exports the runbook and report', async () => {
    await boot();
    document.querySelector<HTMLButtonElement>('[data-sample="ssh-compromise"]')!.click();
    submit();
    await vi.waitFor(() => expect(document.querySelector('.ledger')).not.toBeNull());

    const name = byId<HTMLInputElement>('analyst');
    name.value = 'Asha';
    name.dispatchEvent(new Event('input'));
    document.querySelector<HTMLButtonElement>('[data-role=approve]')!.click();
    expect(byId('status').textContent).toBe('ACT-1 approved.');
    expect(document.querySelector('#audit li')?.textContent).toContain('Asha approved ACT-1');

    const clicks = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);
    const [md, json] = [...document.querySelectorAll<HTMLButtonElement>('.ledger .btn')];
    md!.click();
    json!.click();
    expect(clicks).toHaveBeenCalledTimes(2);
    expect(createObjectURL).toHaveBeenCalledTimes(2);
  });

  it('validates input before calling the server', async () => {
    const fetchMock = await boot();
    submit();
    expect(byId('form-error').hidden).toBe(false);
    expect(byId('form-error').textContent).toMatch(/Paste some log lines/);

    const area = byId<HTMLTextAreaElement>('logs');
    area.value = 'x'.repeat(300 * 1024);
    area.dispatchEvent(new Event('input'));
    submit();
    expect(byId('form-error').textContent).toBe('Logs must be under 256 KB.');
    expect(fetchMock).toHaveBeenCalledTimes(1); // only the status check
  });

  it('shows server errors and restores the introduction', async () => {
    await boot({ analyze: () => ({ status: 429, json: { error: 'Too many requests.' } }) });
    byId<HTMLTextAreaElement>('logs').value = 'some line';
    submit();
    await vi.waitFor(() => expect(byId('form-error').textContent).toBe('Too many requests.'));
    expect(document.querySelector('#results .shloka')).not.toBeNull();
  });

  it('falls back to a generic message when an error has no body', async () => {
    await boot({ analyze: () => ({ status: 500, json: null }) });
    byId<HTMLTextAreaElement>('logs').value = 'some line';
    submit();
    await vi.waitFor(() =>
      expect(byId('form-error').textContent).toBe('Request failed (HTTP 500).'),
    );
  });

  it('switches to rule-only mode when the AI is not configured', async () => {
    await boot({ status: () => ({ status: 200, json: { aiAvailable: false, model: null } }) });
    expect(byId('ai-status').textContent).toBe('Rule engine only: AI not configured');
    expect(byId<HTMLInputElement>('use-ai').disabled).toBe(true);
  });

  it('reports an unreachable server', async () => {
    await boot({ status: () => ({ status: 503, json: {} }) });
    expect(byId('ai-status').textContent).toBe('Cannot reach the server');
  });

  it('loads uploaded files and rejects oversized ones', async () => {
    await boot();
    const input = byId<HTMLInputElement>('file');
    const upload = (file: File) => {
      Object.defineProperty(input, 'files', { value: [file], configurable: true });
      input.dispatchEvent(new Event('change'));
    };
    upload(new File(['line one\nline two'], 'auth.log'));
    await vi.waitFor(() =>
      expect(byId<HTMLTextAreaElement>('logs').value).toBe('line one\nline two'),
    );
    expect(byId('status').textContent).toBe('Loaded auth.log.');

    upload(new File(['x'.repeat(300 * 1024)], 'big.log'));
    expect(byId('form-error').textContent).toMatch(/larger than 256 KB/);
  });
});

describe('dom helpers', () => {
  it('builds elements safely and skips empty children', () => {
    const el = h(
      'p',
      { class: 'a', hidden: true, title: undefined, 'data-x': false },
      'hi',
      null,
      false,
      ['<b>x</b>'],
    );
    expect(el.className).toBe('a');
    expect(el.hasAttribute('hidden')).toBe(true);
    expect(el.hasAttribute('data-x')).toBe(false);
    expect(el.textContent).toBe('hi<b>x</b>');
    expect(el.querySelector('b')).toBeNull();
  });

  it('throws for missing elements and downloads through a temporary link', () => {
    document.body.innerHTML = '';
    expect(() => byId('nope')).toThrow('Missing element #nope');
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);
    download('a.txt', 'hello', 'text/plain');
    expect(click).toHaveBeenCalledOnce();
    expect(document.querySelector('a')).toBeNull();
  });
});
