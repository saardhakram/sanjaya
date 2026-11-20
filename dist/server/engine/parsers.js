/**
 * Deterministic parsers for the log formats Sanjaya understands:
 *  - Linux auth logs (sshd, sudo, useradd/usermod) in syslog or ISO-8601 form
 *  - Web server access logs (Apache/Nginx combined format)
 *  - Firewall logs (UFW / iptables kernel lines)
 * Lines that match none of them are kept as `unknown` so line numbers stay exact.
 */
const MONTHS = {
    Jan: 0,
    Feb: 1,
    Mar: 2,
    Apr: 3,
    May: 4,
    Jun: 5,
    Jul: 6,
    Aug: 7,
    Sep: 8,
    Oct: 9,
    Nov: 10,
    Dec: 11,
};
const IPV4 = String.raw `(?:\d{1,3}\.){3}\d{1,3}`;
const IPV6 = String.raw `[0-9a-fA-F:]{2,39}`;
const IP = `(${IPV4}|${IPV6})`;
const SYSLOG_PREFIX = /^(?<mon>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s(?<time>\d{2}:\d{2}:\d{2})\s(?<host>\S+)\s(?<rest>.*)$/;
const ISO_PREFIX = /^(?<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s(?<host>\S+)\s(?<rest>.*)$/;
const FAILED_PASSWORD = new RegExp(String.raw `Failed (?:password|publickey) for (?<invalid>invalid user )?(?<user>\S+) from ${IP}`);
const ACCEPTED = new RegExp(String.raw `Accepted (?:password|publickey) for (?<user>\S+) from ${IP}`);
const INVALID_USER = new RegExp(String.raw `Invalid user (?<user>\S+) from ${IP}`);
const SUDO = /sudo(?:\[\d+\])?:\s+(?<user>\S+)\s*:.*?USER=(?<target>\S+)\s*;\s*COMMAND=(?<cmd>.+)$/;
const USERADD = /useradd(?:\[\d+\])?:\s+new user: name=(?<user>[^,\s]+)/;
const GROUP_ADD = /(?:usermod|gpasswd)(?:\[\d+\])?:\s+(?:add|adding user) '?(?<user>[^'\s]+)'? to (?:group )?'?(?<group>[^'\s]+)'?/;
const WEB_COMBINED = new RegExp(String.raw `^${IP} \S+ (?<authuser>\S+) \[(?<ts>[^\]]+)\] "(?<method>[A-Z]{3,10}) (?<path>\S+)(?: HTTP/[\d.]+)?" (?<status>\d{3}) (?:\d+|-)(?: "(?<ref>[^"]*)" "(?<ua>[^"]*)")?`);
const WEB_TS = /^(?<day>\d{2})\/(?<mon>[A-Z][a-z]{2})\/(?<year>\d{4}):(?<time>\d{2}:\d{2}:\d{2}) (?<tz>[+-]\d{4})$/;
const FIREWALL = /\[UFW (?<action>BLOCK|ALLOW|AUDIT)\]|IPTABLES|kernel:.*SRC=/;
const FW_SRC = new RegExp(String.raw `SRC=${IP}`);
const FW_DPT = /DPT=(\d{1,5})/;
function syslogTime(mon, day, time, year) {
    const month = MONTHS[mon];
    if (month === undefined)
        return null;
    const [h, m, s] = time.split(':').map(Number);
    return Date.UTC(year, month, Number(day), h, m, s);
}
function parseIso(iso) {
    const t = Date.parse(iso);
    return Number.isNaN(t) ? null : t;
}
function parseWebTime(ts) {
    const m = WEB_TS.exec(ts);
    if (!m?.groups)
        return null;
    const { day, mon, year, time, tz } = m.groups;
    const month = MONTHS[mon ?? ''];
    if (month === undefined || !day || !year || !time || !tz)
        return null;
    const iso = `${year}-${String(month + 1).padStart(2, '0')}-${day}T${time}${tz.slice(0, 3)}:${tz.slice(3)}`;
    return parseIso(iso);
}
function parseAuthBody(rest) {
    let m = FAILED_PASSWORD.exec(rest);
    if (m?.groups) {
        return {
            kind: m.groups.invalid ? 'invalid_user' : 'auth_failure',
            user: m.groups.user,
            srcIp: m[3],
        };
    }
    m = ACCEPTED.exec(rest);
    if (m?.groups)
        return { kind: 'auth_success', user: m.groups.user, srcIp: m[2] };
    m = INVALID_USER.exec(rest);
    if (m?.groups)
        return { kind: 'invalid_user', user: m.groups.user, srcIp: m[2] };
    m = SUDO.exec(rest);
    if (m?.groups) {
        return {
            kind: 'sudo',
            user: m.groups.user,
            targetUser: m.groups.target,
            command: m.groups.cmd?.trim(),
        };
    }
    m = USERADD.exec(rest);
    if (m?.groups)
        return { kind: 'account_created', user: m.groups.user };
    m = GROUP_ADD.exec(rest);
    if (m?.groups)
        return { kind: 'group_change', user: m.groups.user, group: m.groups.group };
    return null;
}
function parseFirewallBody(rest) {
    if (!FIREWALL.test(rest))
        return null;
    const src = FW_SRC.exec(rest)?.[1];
    if (!src)
        return null;
    const dpt = FW_DPT.exec(rest)?.[1];
    const allowed = rest.includes('[UFW ALLOW]') || rest.includes('ACCEPT');
    const event = {
        kind: allowed ? 'firewall_allow' : 'firewall_block',
        srcIp: src,
    };
    if (dpt)
        event.dstPort = Number(dpt);
    return event;
}
function decodePath(path) {
    try {
        return decodeURIComponent(path.replace(/\+/g, ' '));
    }
    catch {
        return path;
    }
}
export function parseLine(raw, line, opts) {
    const base = { line, raw, source: 'unknown', kind: 'other', timestamp: null };
    const web = WEB_COMBINED.exec(raw);
    if (web?.groups) {
        const g = web.groups;
        const event = {
            ...base,
            source: 'web',
            kind: 'http_request',
            timestamp: parseWebTime(g.ts ?? ''),
            srcIp: web[1],
            method: g.method,
            path: decodePath(g.path ?? ''),
            status: Number(g.status),
        };
        if (g.ua !== undefined)
            event.userAgent = g.ua;
        return event;
    }
    const prefix = SYSLOG_PREFIX.exec(raw) ?? ISO_PREFIX.exec(raw);
    if (!prefix?.groups)
        return base;
    const g = prefix.groups;
    const timestamp = g.iso
        ? parseIso(g.iso)
        : syslogTime(g.mon ?? '', g.day ?? '', g.time ?? '', opts.referenceYear);
    const rest = g.rest ?? '';
    const fw = parseFirewallBody(rest);
    if (fw)
        return { ...base, ...fw, source: 'firewall', timestamp, host: g.host };
    const auth = parseAuthBody(rest);
    if (auth)
        return { ...base, ...auth, source: 'auth', timestamp, host: g.host };
    return { ...base, timestamp, host: g.host };
}
export function parseLogs(text, opts) {
    const lines = text.split(/\r?\n/);
    const events = [];
    const bySource = { auth: 0, web: 0, firewall: 0, unknown: 0 };
    let linesTotal = 0;
    lines.forEach((raw, i) => {
        if (raw.trim() === '')
            return;
        linesTotal++;
        const event = parseLine(raw, i + 1, opts);
        bySource[event.source]++;
        events.push(event);
    });
    return {
        events,
        linesTotal,
        linesParsed: linesTotal - bySource.unknown,
        bySource,
    };
}
