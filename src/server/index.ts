import { GeminiClient } from './agent/model.js';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { log } from './logger.js';
import { AnalysisService } from './service.js';

const config = loadConfig();
const client = config.geminiApiKey ? new GeminiClient(config.geminiApiKey) : undefined;
const service = new AnalysisService(config, client);
const app = createApp({ config, service });

const server = app.listen(config.port, () => {
  log('info', 'server_started', { port: config.port, aiAvailable: service.aiAvailable });
});

function shutdown(signal: string): void {
  log('info', 'shutdown', { signal });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
