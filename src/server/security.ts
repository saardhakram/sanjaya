import type { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';

/** Strict security headers: no inline script or style, no framing, no third-party origins. */
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  strictTransportSecurity: { maxAge: 63_072_000, includeSubDomains: true },
});

export function permissionsPolicy(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
}

/** Rejects cross-site browser requests to the API (CSRF / abuse from other origins). */
export function sameOrigin(req: Request, res: Response, next: NextFunction): void {
  const origin = req.get('origin');
  if (origin) {
    let host: string | undefined;
    try {
      host = new URL(origin).host;
    } catch {
      host = undefined;
    }
    if (host !== req.get('host')) {
      res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
      return;
    }
  }
  next();
}

/** Fixed-window, per-client rate limiter (in memory, per instance). */
export function rateLimiter(limitPerMinute: number, now: () => number = Date.now) {
  const windows = new Map<string, { start: number; count: number }>();
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip ?? 'unknown';
    const t = now();
    let w = windows.get(key);
    if (!w || t - w.start >= 60_000) {
      w = { start: t, count: 0 };
      windows.set(key, w);
      if (windows.size > 10_000) {
        for (const [k, v] of windows) if (t - v.start >= 60_000) windows.delete(k);
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
