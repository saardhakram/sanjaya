import type { DetectorId, Finding, LogEvent, Severity } from '../../shared/types.js';

/**
 * Deterministic detection rules. Every threshold is a named constant so the
 * behaviour is explainable and covered by tests. Scores are 0–100.
 */
export const THRESHOLDS = {
  bruteforceFailures: 5,
  bruteforceWindowMs: 10 * 60_000,
  sprayDistinctUsers: 4,
  portScanDistinctPorts: 10,
  portScanWindowMs: 5 * 60_000,
  enumeration404s: 15,
  enumerationWindowMs: 5 * 60_000,
  maxEvidence: 25,
} as const;

const SHELL_COMMAND =
  /(^|\/)(bash|sh|zsh|dash|su)(\s|$)|\bsu\s+-|python[\d.]*\s+-c|chmod\s+[0-7]*[4-7][0-7]{3}|\/etc\/(shadow|sudoers)/;
const PRIVILEGED_GROUPS = new Set(['sudo', 'wheel', 'admin', 'root', 'adm', 'docker']);

const WEB_SIGNATURES: readonly { category: string; pattern: RegExp; score: number }[] = [
  {
    category: 'SQL injection',
    pattern:
      /('|%27)\s*(or|and)\s+['"\d]|union(\s|\+|%20)+select|sleep\(\d+\)|information_schema|--\s*$|;\s*drop\s+table/i,
    score: 75,
  },
  {
    category: 'Command injection',
    pattern: /[;|`]\s*(cat|wget|curl|nc|bash|sh|id|whoami|uname)\b|\$\((?:[^)]*)\)/i,
    score: 80,
  },
  {
    category: 'Path traversal',
    pattern: /\.\.\/|\.\.%2f|%2e%2e|\/etc\/passwd|win\.ini/i,
    score: 72,
  },
  {
    category: 'Cross-site scripting',
    pattern: /<script|javascript:|onerror\s*=|onload\s*=/i,
    score: 60,
  },
  {
    category: 'Sensitive file probe',
    pattern: /\/\.env\b|\/\.git\/|\/wp-config\.php|\/phpmyadmin|\/\.aws\/|\/server-status/i,
    score: 55,
  },
];

const SCANNER_AGENTS =
  /sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|zgrab|nuclei|acunetix|ffuf|hydra/i;

const PROMPT_INJECTION =
  /ignore (all |any )?(previous|prior|above) (instructions|prompts)|disregard (the )?(system|previous)|you are now (a|an|in)|system prompt|mark (this|it) as (benign|safe|false positive)|do not (report|flag|alert)/i;

export function severityFor(score: number): Severity {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

interface FindingDraft {
  detector: DetectorId;
  title: string;
  score: number;
  techniques: string[];
  ip?: string;
  user?: string;
  events: LogEvent[];
  details: string;
}

function timeBounds(events: readonly LogEvent[]): { first: number | null; last: number | null } {
  const times = events.map((e) => e.timestamp).filter((t): t is number => t !== null);
  if (times.length === 0) return { first: null, last: null };
  return { first: Math.min(...times), last: Math.max(...times) };
}

function groupBy<K>(
  events: readonly LogEvent[],
  key: (e: LogEvent) => K | undefined,
): Map<K, LogEvent[]> {
  const map = new Map<K, LogEvent[]>();
  for (const e of events) {
    const k = key(e);
    if (k === undefined) continue;
    const list = map.get(k);
    if (list) list.push(e);
    else map.set(k, [e]);
  }
  return map;
}

/**
 * Largest number of events falling inside any window of `windowMs`.
 * Events without timestamps are counted together (window unknown).
 */
export function maxInWindow(events: readonly LogEvent[], windowMs: number): LogEvent[] {
  const timed = events
    .filter((e) => e.timestamp !== null)
    .sort((a, b) => a.timestamp! - b.timestamp!);
  if (timed.length === 0) return [...events];
  let best: LogEvent[] = [];
  let start = 0;
  for (let end = 0; end < timed.length; end++) {
    while (timed[end]!.timestamp! - timed[start]!.timestamp! > windowMs) start++;
    if (end - start + 1 > best.length) best = timed.slice(start, end + 1);
  }
  return best;
}

function detectBruteforce(events: readonly LogEvent[]): FindingDraft[] {
  const failures = events.filter((e) => e.kind === 'auth_failure' || e.kind === 'invalid_user');
  const drafts: FindingDraft[] = [];
  for (const [ip, list] of groupBy(failures, (e) => e.srcIp)) {
    const burst = maxInWindow(list, THRESHOLDS.bruteforceWindowMs);
    const users = new Set(list.map((e) => e.user).filter(Boolean));
    if (burst.length >= THRESHOLDS.bruteforceFailures) {
      drafts.push({
        detector: 'ssh_bruteforce',
        title: `SSH brute force from ${ip}`,
        score: clamp(60 + Math.min(20, burst.length)),
        techniques: ['T1110.001'],
        ip,
        events: list,
        details: `${list.length} failed SSH logins (peak ${burst.length} within 10 min) against ${users.size} account(s).`,
      });
    }
    if (users.size >= THRESHOLDS.sprayDistinctUsers) {
      drafts.push({
        detector: 'password_spray',
        title: `Password spraying from ${ip}`,
        score: clamp(62 + users.size * 2),
        techniques: ['T1110.003'],
        ip,
        events: list,
        details: `Failed logins for ${users.size} different usernames: ${[...users].slice(0, 8).join(', ')}.`,
      });
    }
  }
  return drafts;
}

function detectBruteforceSuccess(
  events: readonly LogEvent[],
  bruteIps: ReadonlySet<string>,
): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const successes = events.filter(
    (e) => e.kind === 'auth_success' && e.srcIp && bruteIps.has(e.srcIp),
  );
  for (const [ip, list] of groupBy(successes, (e) => e.srcIp)) {
    const firstFailure = events.find(
      (e) => e.srcIp === ip && (e.kind === 'auth_failure' || e.kind === 'invalid_user'),
    );
    const after = list.filter((s) => !firstFailure || s.line > firstFailure.line);
    if (after.length === 0) continue;
    const user = after[0]!.user;
    drafts.push({
      detector: 'bruteforce_success',
      title: `Successful login after brute force: ${user ?? 'unknown'} from ${ip}`,
      score: 92,
      techniques: ['T1078', 'T1110.001'],
      ip,
      ...(user ? { user } : {}),
      events: after,
      details: `Account "${user ?? 'unknown'}" logged in from ${ip} after repeated failures — likely compromised credentials.`,
    });
  }
  return drafts;
}

function detectPrivilegeEscalation(events: readonly LogEvent[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const sudoShells = events.filter(
    (e) => e.kind === 'sudo' && e.targetUser === 'root' && SHELL_COMMAND.test(e.command ?? ''),
  );
  for (const [user, list] of groupBy(sudoShells, (e) => e.user)) {
    drafts.push({
      detector: 'privilege_escalation',
      title: `Root shell via sudo by ${user}`,
      score: 78,
      techniques: ['T1548.003', 'T1059.004'],
      user,
      events: list,
      details: `${user} ran ${list.length} privileged command(s) as root, e.g. "${(list[0]!.command ?? '').slice(0, 80)}".`,
    });
  }
  const groupAdds = events.filter(
    (e) => e.kind === 'group_change' && PRIVILEGED_GROUPS.has(e.group ?? ''),
  );
  for (const [user, list] of groupBy(groupAdds, (e) => e.user)) {
    drafts.push({
      detector: 'privilege_escalation',
      title: `${user} added to privileged group`,
      score: 74,
      techniques: ['T1098.007'],
      user,
      events: list,
      details: `Account "${user}" was added to: ${[...new Set(list.map((e) => e.group))].join(', ')}.`,
    });
  }
  return drafts;
}

function detectAccountPersistence(events: readonly LogEvent[]): FindingDraft[] {
  return [
    ...groupBy(
      events.filter((e) => e.kind === 'account_created'),
      (e) => e.user,
    ),
  ].map(([user, list]) => ({
    detector: 'account_persistence' as const,
    title: `New local account created: ${user}`,
    score: 55,
    techniques: ['T1136.001'],
    user,
    events: list,
    details: `A local account "${user}" was created; verify it was authorised.`,
  }));
}

function detectPortScan(events: readonly LogEvent[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const fw = events.filter((e) => e.source === 'firewall' && e.dstPort !== undefined);
  for (const [ip, list] of groupBy(fw, (e) => e.srcIp)) {
    const burst = maxInWindow(list, THRESHOLDS.portScanWindowMs);
    const ports = new Set(burst.map((e) => e.dstPort));
    if (ports.size >= THRESHOLDS.portScanDistinctPorts) {
      drafts.push({
        detector: 'port_scan',
        title: `Port scan from ${ip}`,
        score: clamp(45 + Math.min(20, ports.size)),
        techniques: ['T1046'],
        ip,
        events: list,
        details: `${ports.size} distinct destination ports probed within 5 min (${list.length} firewall events).`,
      });
    }
  }
  return drafts;
}

function detectWeb(events: readonly LogEvent[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const web = events.filter((e) => e.kind === 'http_request');

  for (const [ip, list] of groupBy(web, (e) => e.srcIp)) {
    for (const sig of WEB_SIGNATURES) {
      const hits = list.filter((e) => sig.pattern.test(e.path ?? ''));
      if (hits.length === 0) continue;
      const succeeded = hits.filter((e) => (e.status ?? 0) >= 200 && (e.status ?? 0) < 300);
      const bonus = succeeded.length > 0 && sig.category !== 'Sensitive file probe' ? 12 : 0;
      drafts.push({
        detector: 'web_attack',
        title: `${sig.category} attempts from ${ip}`,
        score: clamp(sig.score + Math.min(8, hits.length) + bonus),
        techniques: sig.category === 'Sensitive file probe' ? ['T1595.002'] : ['T1190'],
        ip,
        events: hits,
        details:
          `${hits.length} request(s) matching ${sig.category.toLowerCase()} patterns` +
          (succeeded.length > 0
            ? `; ${succeeded.length} returned HTTP 2xx (possible success).`
            : '; none returned 2xx.'),
      });
    }

    const scanners = list.filter((e) => SCANNER_AGENTS.test(e.userAgent ?? ''));
    if (scanners.length > 0) {
      const tool = SCANNER_AGENTS.exec(scanners[0]!.userAgent ?? '')?.[0] ?? 'scanner';
      drafts.push({
        detector: 'web_scanner',
        title: `Automated attack tool (${tool}) from ${ip}`,
        score: clamp(50 + Math.min(15, scanners.length)),
        techniques: ['T1595.002'],
        ip,
        events: scanners,
        details: `${scanners.length} request(s) with a known offensive-tool user agent ("${tool}").`,
      });
    }

    const notFound = list.filter((e) => e.status === 404);
    const burst = maxInWindow(notFound, THRESHOLDS.enumerationWindowMs);
    if (burst.length >= THRESHOLDS.enumeration404s) {
      drafts.push({
        detector: 'web_enumeration',
        title: `Directory enumeration from ${ip}`,
        score: clamp(45 + Math.min(15, Math.floor(burst.length / 3))),
        techniques: ['T1595.003'],
        ip,
        events: notFound,
        details: `${burst.length} HTTP 404 responses within 5 min — wordlist-based content discovery.`,
      });
    }
  }
  return drafts;
}

function detectPromptInjection(events: readonly LogEvent[]): FindingDraft[] {
  const hits = events.filter((e) => PROMPT_INJECTION.test(e.raw));
  if (hits.length === 0) return [];
  const byIp = groupBy(hits, (e) => e.srcIp ?? 'unattributed');
  return [...byIp].map(([ip, list]) => ({
    detector: 'ai_prompt_injection' as const,
    title: `Prompt-injection text planted in logs${ip === 'unattributed' ? '' : ` from ${ip}`}`,
    score: 50,
    techniques: ['AML.T0051'],
    ...(ip === 'unattributed' ? {} : { ip }),
    events: list,
    details: `${list.length} log line(s) contain instructions aimed at AI tools (e.g. "ignore previous instructions"). Treated strictly as data.`,
  }));
}

/** Runs every detector and returns findings sorted by score (highest first). */
export function runDetectors(events: readonly LogEvent[]): Finding[] {
  const brute = detectBruteforce(events);
  const bruteIps = new Set(brute.filter((d) => d.detector === 'ssh_bruteforce').map((d) => d.ip!));
  const drafts = [
    ...brute,
    ...detectBruteforceSuccess(events, bruteIps),
    ...detectPrivilegeEscalation(events),
    ...detectAccountPersistence(events),
    ...detectPortScan(events),
    ...detectWeb(events),
    ...detectPromptInjection(events),
  ];

  return drafts
    .sort((a, b) => b.score - a.score || a.events[0]!.line - b.events[0]!.line)
    .map((d, i) => {
      const { first, last } = timeBounds(d.events);
      const finding: Finding = {
        id: `F-${String(i + 1).padStart(3, '0')}`,
        detector: d.detector,
        title: d.title,
        severity: severityFor(d.score),
        score: d.score,
        techniques: d.techniques,
        firstSeen: first,
        lastSeen: last,
        count: d.events.length,
        evidence: d.events.slice(0, THRESHOLDS.maxEvidence).map((e) => e.line),
        details: d.details,
      };
      if (d.ip) finding.ip = d.ip;
      if (d.user) finding.user = d.user;
      return finding;
    });
}
