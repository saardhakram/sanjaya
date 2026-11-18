import { buildApp } from './bootstrap.js';
import { log } from './logger.js';

// Container entrypoint (Cloud Run / Docker / local): listens on $PORT.
const { app, service, config } = buildApp();

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
