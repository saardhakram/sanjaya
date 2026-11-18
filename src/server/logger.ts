/**
 * Structured JSON logging. On Cloud Run, stdout lines in this shape are parsed
 * by Google Cloud Logging (severity + jsonPayload). Never logs user log text.
 */
type Level = 'info' | 'warn' | 'error';

const SEVERITY: Record<Level, string> = { info: 'INFO', warn: 'WARNING', error: 'ERROR' };

export function log(level: Level, message: string, fields: Record<string, unknown> = {}): void {
  if (process.env.NODE_ENV === 'test') return;
  const line = JSON.stringify({ severity: SEVERITY[level], message, ...fields });
  if (level === 'info') console.log(line);
  else console.error(line);
}
