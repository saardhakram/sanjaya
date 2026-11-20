import { createHash } from 'node:crypto';
/** Small TTL + LRU cache. Identical log submissions are served with zero model tokens. */
export class TtlCache {
    maxEntries;
    ttlMs;
    now;
    entries = new Map();
    constructor(maxEntries, ttlMs, now = Date.now) {
        this.maxEntries = maxEntries;
        this.ttlMs = ttlMs;
        this.now = now;
    }
    get(key) {
        const hit = this.entries.get(key);
        if (!hit)
            return undefined;
        if (hit.expires <= this.now()) {
            this.entries.delete(key);
            return undefined;
        }
        this.entries.delete(key);
        this.entries.set(key, hit);
        return hit.value;
    }
    set(key, value) {
        this.entries.delete(key);
        this.entries.set(key, { value, expires: this.now() + this.ttlMs });
        while (this.entries.size > this.maxEntries) {
            const oldest = this.entries.keys().next().value;
            if (oldest === undefined)
                break;
            this.entries.delete(oldest);
        }
    }
    get size() {
        return this.entries.size;
    }
}
export function cacheKey(...parts) {
    const hash = createHash('sha256');
    for (const p of parts)
        hash.update(p).update('\u0000');
    return hash.digest('hex');
}
