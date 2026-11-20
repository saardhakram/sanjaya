const CSP = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    'upgrade-insecure-requests',
].join('; ');
const HEADERS = {
    'Content-Security-Policy': CSP,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-DNS-Prefetch-Control': 'off',
    'Origin-Agent-Cluster': '?1',
};
/** Strict security headers: no inline script or style, no framing, no third-party origins. */
export function securityHeaders(_req, res, next) {
    for (const [name, value] of Object.entries(HEADERS))
        res.setHeader(name, value);
    next();
}
export function permissionsPolicy(_req, res, next) {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
}
/** Rejects cross-site browser requests to the API (CSRF / abuse from other origins). */
export function sameOrigin(req, res, next) {
    const origin = req.get('origin');
    if (origin) {
        let host;
        try {
            host = new URL(origin).host;
        }
        catch {
            host = undefined;
        }
        // Hosting proxies may rewrite Host; the first X-Forwarded-Host value is the public host.
        const forwarded = req.get('x-forwarded-host')?.split(',')[0]?.trim();
        if (!host || (host !== req.get('host') && host !== forwarded)) {
            res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
            return;
        }
    }
    next();
}
/** Fixed-window, per-client rate limiter (in memory, per instance). */
export function rateLimiter(limitPerMinute, now = Date.now) {
    const windows = new Map();
    return (req, res, next) => {
        const key = req.ip ?? 'unknown';
        const t = now();
        let w = windows.get(key);
        if (!w || t - w.start >= 60_000) {
            w = { start: t, count: 0 };
            windows.set(key, w);
            if (windows.size > 10_000) {
                for (const [k, v] of windows)
                    if (t - v.start >= 60_000)
                        windows.delete(k);
            }
        }
        w.count++;
        res.setHeader('RateLimit-Limit', String(limitPerMinute));
        res.setHeader('RateLimit-Remaining', String(Math.max(0, limitPerMinute - w.count)));
        if (w.count > limitPerMinute) {
            res.setHeader('Retry-After', String(Math.ceil((w.start + 60_000 - t) / 1000)));
            res.status(429).json({ error: 'Too many requests. Please wait a minute and try again.' });
            return;
        }
        next();
    };
}
