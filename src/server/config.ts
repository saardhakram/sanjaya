/** Runtime configuration, read once from environment variables. */
export interface Config {
  port: number;
  geminiApiKey: string | undefined;
  models: string[];
  maxLogBytes: number;
  maxLines: number;
  referenceYear: number;
  rateLimitPerMinute: number;
  agent: { maxTurns: number; callTimeoutMs: number; totalTimeoutMs: number };
  cache: { maxEntries: number; ttlMs: number };
}

function int(value: string | undefined, fallback: number): number {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Trimmed value, or undefined when unset or blank. */
function text(value: string | undefined): string | undefined {
  const trimmed = value?.trim() ?? '';
  return trimmed.length > 0 ? trimmed : undefined;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const primary = text(env.GEMINI_MODEL) ?? 'gemini-3.1-flash-lite';
  const fallback = text(env.GEMINI_FALLBACK_MODEL) ?? 'gemini-3.5-flash';
  return {
    port: int(env.PORT, 8080),
    geminiApiKey: text(env.GEMINI_API_KEY),
    models: [...new Set([primary, fallback])],
    maxLogBytes: int(env.MAX_LOG_BYTES, 256 * 1024),
    maxLines: int(env.MAX_LOG_LINES, 5000),
    referenceYear: int(env.REFERENCE_YEAR, new Date().getUTCFullYear()),
    rateLimitPerMinute: int(env.RATE_LIMIT_PER_MINUTE, 20),
    agent: {
      maxTurns: int(env.AGENT_MAX_TURNS, 6),
      callTimeoutMs: int(env.AGENT_CALL_TIMEOUT_MS, 20_000),
      totalTimeoutMs: int(env.AGENT_TOTAL_TIMEOUT_MS, 50_000),
    },
    cache: { maxEntries: 100, ttlMs: 15 * 60_000 },
  };
}
