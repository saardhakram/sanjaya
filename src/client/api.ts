import type { AnalysisResult } from '../shared/types.js';

export interface ServerStatus {
  aiAvailable: boolean;
  model: string | null;
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    if (body.error) return body.error;
  } catch {
    /* fall through */
  }
  return `Request failed (HTTP ${res.status}).`;
}

export async function fetchStatus(): Promise<ServerStatus> {
  const res = await fetch('/api/status');
  if (!res.ok) throw new Error(await errorMessage(res));
  return (await res.json()) as ServerStatus;
}

export async function analyze(
  logs: string,
  useAi: boolean,
  signal: AbortSignal,
): Promise<AnalysisResult> {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs, useAi }),
    signal,
  });
  if (!res.ok) throw new Error(await errorMessage(res));
  return (await res.json()) as AnalysisResult;
}
