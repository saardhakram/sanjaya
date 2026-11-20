import { maxInWindow } from '../engine/detectors.js';
export const FEATURES = [
    { key: 'authAttempts', label: 'Login attempts', scale: 'count', group: 'auth' },
    { key: 'authFailures', label: 'Failed logins', scale: 'count', group: 'auth' },
    { key: 'authFailRatio', label: 'Failed login share', scale: 'ratio', group: 'auth' },
    { key: 'invalidUserRatio', label: 'Logins to non-existent users', scale: 'ratio', group: 'auth' },
    { key: 'usersTried', label: 'Different usernames tried', scale: 'count', group: 'auth' },
    { key: 'requests', label: 'Web requests', scale: 'count', group: 'web' },
    { key: 'peakRequestsPerMinute', label: 'Peak requests per minute', scale: 'count', group: 'web' },
    { key: 'http4xxRatio', label: 'Client errors (4xx)', scale: 'ratio', group: 'web' },
    { key: 'http5xxRatio', label: 'Server errors (5xx)', scale: 'ratio', group: 'web' },
    { key: 'distinctPaths', label: 'Different URLs requested', scale: 'count', group: 'web' },
    { key: 'oddCharRatio', label: 'Code-like characters in URLs', scale: 'ratio', group: 'web' },
    { key: 'meanUrlLength', label: 'Average URL length', scale: 'chars', group: 'web' },
    {
        key: 'nonBrowserRatio',
        label: 'Requests from non-browser tools',
        scale: 'ratio',
        group: 'web',
    },
    { key: 'firewallEvents', label: 'Firewall events', scale: 'count', group: 'network' },
    { key: 'firewallBlockRatio', label: 'Firewall-blocked share', scale: 'ratio', group: 'network' },
    { key: 'distinctPorts', label: 'Different ports contacted', scale: 'count', group: 'network' },
];
export const GROUPS = ['auth', 'web', 'network'];
/** Indices into FEATURES for one group. */
export function groupIndices(group) {
    return FEATURES.flatMap((f, i) => (f.group === group ? [i] : []));
}
/** Characters that rarely appear in ordinary URLs but are common in payloads. */
const ODD_CHARS = new Set([...`'"<>;|\`$(){}[]\\!*^~`]);
/**
 * Share of characters in a URL that look like code rather than an address.
 * Paths arrive already URL-decoded by the parser, so any %XX left over means
 * double encoding, a classic filter-evasion trick, and counts as odd.
 */
export function oddCharShare(text) {
    if (text.length === 0)
        return 0;
    let odd = 0;
    for (const ch of text)
        if (ODD_CHARS.has(ch))
            odd++;
    odd += (text.match(/\.\.|\/\/|%[0-9a-f]{2}/gi) ?? []).length * 2;
    return Math.min(1, odd / text.length);
}
const isAuthFailure = (e) => e.kind === 'auth_failure' || e.kind === 'invalid_user';
/** Pseudo-count that shrinks shares from tiny samples towards zero in the model input. */
export const RATIO_PRIOR = 4;
function share(k, n) {
    return { k, n };
}
function mean(values) {
    return values.length === 0 ? 0 : values.reduce((a, b) => a + b, 0) / values.length;
}
function rawValue(m) {
    return typeof m === 'number' ? m : m.n === 0 ? 0 : m.k / m.n;
}
function modelValue(m) {
    return typeof m === 'number' ? Math.log1p(m) : m.k / (m.n + RATIO_PRIOR);
}
export function profileFor(ip, events) {
    const auth = events.filter((e) => isAuthFailure(e) || e.kind === 'auth_success');
    const failures = auth.filter(isAuthFailure);
    const http = events.filter((e) => e.kind === 'http_request');
    const fw = events.filter((e) => e.kind === 'firewall_block' || e.kind === 'firewall_allow');
    const paths = http.map((e) => e.path ?? '');
    const oddChars = paths.reduce((sum, p) => sum + oddCharShare(p), 0);
    const measured = [
        auth.length,
        failures.length,
        share(failures.length, auth.length),
        share(auth.filter((e) => e.kind === 'invalid_user').length, auth.length),
        new Set(auth.map((e) => e.user).filter(Boolean)).size,
        http.length,
        http.length === 0 ? 0 : maxInWindow(http, 60_000).length,
        share(http.filter((e) => (e.status ?? 0) >= 400 && (e.status ?? 0) < 500).length, http.length),
        share(http.filter((e) => (e.status ?? 0) >= 500).length, http.length),
        new Set(paths.map((p) => p.split('?')[0])).size,
        share(oddChars, http.length),
        mean(paths.map((p) => p.length)),
        share(http.filter((e) => !/mozilla/i.test(e.userAgent ?? '')).length, http.length),
        fw.length,
        share(fw.filter((e) => e.kind === 'firewall_block').length, fw.length),
        new Set(fw.map((e) => e.dstPort).filter((p) => p !== undefined)).size,
    ];
    const groups = [];
    if (auth.length > 0)
        groups.push('auth');
    if (http.length > 0)
        groups.push('web');
    if (fw.length > 0)
        groups.push('network');
    return {
        ip,
        raw: measured.map(rawValue),
        vector: measured.map(modelValue),
        groups,
        events: [...events],
    };
}
/** One profile per source IP that appears in the events. */
export function profilesFrom(events) {
    const byIp = new Map();
    for (const e of events) {
        if (!e.srcIp)
            continue;
        const list = byIp.get(e.srcIp);
        if (list)
            list.push(e);
        else
            byIp.set(e.srcIp, [e]);
    }
    return [...byIp].map(([ip, list]) => profileFor(ip, list));
}
