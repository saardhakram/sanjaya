import type * as GenAI from '@google/genai';
import { afterEach, describe, expect, it, vi } from 'vitest';

const generateContent = vi.fn();

vi.mock('@google/genai', async (importOriginal) => {
  const actual = await importOriginal<typeof GenAI>();
  return {
    ...actual,
    GoogleGenAI: vi.fn(function () {
      return { models: { generateContent } };
    }),
  };
});

const { GeminiClient } = await import('../src/server/agent/model.js');
const { log } = await import('../src/server/logger.js');

describe('GeminiClient', () => {
  const req = {
    model: 'gemini-test',
    systemInstruction: 'sys',
    contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
    tools: [],
    signal: new AbortController().signal,
  };

  it('sends function-calling config and maps calls, content and usage', async () => {
    const content = {
      role: 'model',
      parts: [{ functionCall: { name: 'get_playbook', args: {} }, thoughtSignature: 'sig' }],
    };
    generateContent.mockResolvedValueOnce({
      candidates: [{ content }],
      functionCalls: [{ id: 'x1', name: 'get_playbook', args: { a: 1 } }, { name: undefined }],
      usageMetadata: { promptTokenCount: 120, candidatesTokenCount: 30 },
    });
    const out = await new GeminiClient('key').generate(req);
    const sent = generateContent.mock.calls[0]![0];
    expect(sent.model).toBe('gemini-test');
    expect(sent.config.toolConfig.functionCallingConfig.mode).toBe('ANY');
    expect(sent.config.systemInstruction).toBe('sys');
    expect(sent.config.safetySettings.length).toBeGreaterThan(0);
    expect(out.content).toBe(content);
    expect(out.calls).toEqual([
      { id: 'x1', name: 'get_playbook', args: { a: 1 } },
      { name: '', args: {} },
    ]);
    expect(out.usage).toEqual({ input: 120, output: 30 });
  });

  it('handles empty responses', async () => {
    generateContent.mockResolvedValueOnce({});
    const out = await new GeminiClient('key').generate(req);
    expect(out).toEqual({
      content: { role: 'model', parts: [] },
      calls: [],
      usage: { input: 0, output: 0 },
    });
  });
});

describe('logger', () => {
  const env = process.env.NODE_ENV;
  afterEach(() => {
    process.env.NODE_ENV = env;
    vi.restoreAllMocks();
  });

  it('writes Cloud Logging-compatible JSON lines', () => {
    process.env.NODE_ENV = 'production';
    const out = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const err = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    log('info', 'hello', { a: 1 });
    log('warn', 'careful');
    expect(JSON.parse(out.mock.calls[0]![0] as string)).toEqual({
      severity: 'INFO',
      message: 'hello',
      a: 1,
    });
    expect(JSON.parse(err.mock.calls[0]![0] as string)).toMatchObject({ severity: 'WARNING' });
  });
});
