import { GeminiClient } from './agent/model.js';
import { createApp } from './app.js';
import { loadConfig, type Config } from './config.js';
import { AnalysisService } from './service.js';

/** Wires config, the Gemini client and the service into an Express app. */
export function buildApp(config: Config = loadConfig()) {
  const client = config.geminiApiKey ? new GeminiClient(config.geminiApiKey) : undefined;
  const service = new AnalysisService(config, client);
  return { app: createApp({ config, service }), service, config };
}
