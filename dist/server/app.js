import { randomUUID } from 'node:crypto';
import path from 'node:path';
import express, {} from 'express';
import { z } from 'zod';
import { log } from './logger.js';
import { permissionsPolicy, rateLimiter, sameOrigin, securityHeaders } from './security.js';
// Built static assets (see scripts/build-client.mjs); the process runs from the project root.
const DEFAULT_PUBLIC_DIR = path.resolve(process.cwd(), 'dist/public');
export function createApp({ config, service, publicDir = DEFAULT_PUBLIC_DIR }) {
    const app = express();
    app.disable('x-powered-by');
    app.set('trust proxy', 1);
    const AnalyzeBody = z.object({
        logs: z
            .string()
            .min(1, 'Paste or upload some log lines first.')
            .refine((s) => Buffer.byteLength(s, 'utf8') <= config.maxLogBytes, {
            message: `Logs must be under ${Math.round(config.maxLogBytes / 1024)} KB.`,
        })
            .refine((s) => s.split('\n').length <= config.maxLines, {
            message: `Logs must have at most ${config.maxLines} lines.`,
        }),
        useAi: z.boolean().default(true),
    });
    app.use((req, res, next) => {
        res.locals.requestId = randomUUID();
        res.setHeader('X-Request-Id', res.locals.requestId);
        next();
    });
    app.use(securityHeaders);
    app.use(permissionsPolicy);
    app.get('/healthz', (_req, res) => {
        res.json({ status: 'ok' });
    });
    const api = express.Router();
    api.use(sameOrigin);
    api.use(rateLimiter(config.rateLimitPerMinute));
    api.use(express.json({ limit: config.maxLogBytes + 16 * 1024 }));
    api.use((_req, res, next) => {
        res.setHeader('Cache-Control', 'no-store');
        next();
    });
    api.get('/status', (_req, res) => {
        res.json({
            aiAvailable: service.aiAvailable,
            model: service.aiAvailable ? config.models[0] : null,
            limits: { maxLogBytes: config.maxLogBytes, maxLines: config.maxLines },
        });
    });
    api.post('/analyze', async (req, res, next) => {
        const parsed = AnalyzeBody.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid request.' });
            return;
        }
        try {
            const result = await service.analyze({
                ...parsed.data,
                requestId: res.locals.requestId,
            });
            res.json(result);
        }
        catch (err) {
            next(err);
        }
    });
    api.use((_req, res) => {
        res.status(404).json({ error: 'Not found.' });
    });
    app.use('/api', api);
    app.use(express.static(publicDir, {
        index: 'index.html',
        dotfiles: 'deny',
        // Pages and scripts are revalidated on every load; fonts never change.
        setHeaders: (res, filePath) => {
            res.setHeader('Cache-Control', filePath.includes(`${path.sep}fonts${path.sep}`)
                ? 'public, max-age=31536000, immutable'
                : 'public, max-age=0, must-revalidate');
        },
    }));
    // Central error handler: generic message for clients, details only in logs.
    app.use((err, _req, res, _next) => {
        const status = typeof err === 'object' && err !== null && 'status' in err && typeof err.status === 'number'
            ? err.status
            : 500;
        const requestId = res.locals.requestId;
        if (status >= 500) {
            log('error', 'unhandled_error', {
                requestId,
                error: err instanceof Error ? err.message : 'unknown',
            });
        }
        const message = status === 413
            ? 'Upload too large.'
            : status === 400
                ? 'Malformed request body.'
                : 'Something went wrong. Please try again.';
        res.status(status).json({ error: message, requestId });
    });
    return app;
}
