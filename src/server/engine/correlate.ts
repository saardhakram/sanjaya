import { TACTIC_ORDER, tacticsFor } from '../../shared/mitre.js';
import type {
  DetectorId,
  Finding,
  Incident,
  LogEvent,
  PlaybookActionId,
  ProposedActionInput,
} from '../../shared/types.js';
import { severityFor } from './detectors.js';

/**
 * Groups findings into incidents by linking the entities they share:
 *  - a finding's own IP and user
 *  - a successful login (user ↔ source IP) when that IP is already suspicious
 *  - an account created or modified through sudo by an already-linked user
 * Uses union-find so chains like scan → brute force → login → sudo → backdoor
 * account collapse into one multi-stage incident.
 */

class UnionFind {
  private readonly parent = new Map<string, string>();

  find(x: string): string {
    let root = x;
    while (this.parent.has(root) && this.parent.get(root) !== root) root = this.parent.get(root)!;
    if (!this.parent.has(x)) this.parent.set(x, x);
    let node = x;
    while (node !== root) {
      const next = this.parent.get(node)!;
      this.parent.set(node, root);
      node = next;
    }
    return root;
  }

  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(rb, ra);
  }
}

const ACCOUNT_IN_COMMAND =
  /\b(?:useradd|adduser|usermod|gpasswd|passwd)\b.*?\b([a-z_][a-z0-9_-]{0,31})\s*$/;

const BASELINE: Readonly<
  Record<DetectorId, readonly { action: PlaybookActionId; on?: 'ip' | 'user' }[]>
> = {
  bruteforce_success: [
    { action: 'lock_account', on: 'user' },
    { action: 'terminate_sessions', on: 'user' },
    { action: 'force_password_reset', on: 'user' },
    { action: 'block_ip', on: 'ip' },
    { action: 'preserve_evidence' },
    { action: 'escalate_to_human' },
  ],
  privilege_escalation: [{ action: 'review_sudoers' }, { action: 'escalate_to_human' }],
  account_persistence: [{ action: 'remove_unauthorized_account', on: 'user' }],
  ssh_bruteforce: [{ action: 'block_ip', on: 'ip' }, { action: 'rate_limit_ssh' }],
  password_spray: [{ action: 'block_ip', on: 'ip' }, { action: 'disable_password_auth' }],
  web_attack: [
    { action: 'add_waf_rule', on: 'ip' },
    { action: 'patch_web_app' },
    { action: 'block_ip', on: 'ip' },
  ],
  web_scanner: [{ action: 'add_waf_rule', on: 'ip' }],
  web_enumeration: [{ action: 'add_waf_rule', on: 'ip' }],
  port_scan: [{ action: 'block_ip', on: 'ip' }],
  ai_prompt_injection: [{ action: 'preserve_evidence' }, { action: 'escalate_to_human' }],
};

const BASELINE_REASON: Readonly<Record<DetectorId, string>> = {
  bruteforce_success: 'Credentials appear compromised after a brute-force attack.',
  privilege_escalation: 'Root access was obtained; confirm who holds elevated rights.',
  account_persistence: 'An account created during the attack is a likely backdoor.',
  ssh_bruteforce: 'Stop ongoing password guessing from this source.',
  password_spray: 'Stop spraying and remove password-guessing as an attack path.',
  web_attack: 'Block exploitation attempts and fix the targeted input handling.',
  web_scanner: 'Block automated offensive tooling.',
  web_enumeration: 'Block content discovery from this source.',
  port_scan: 'Block reconnaissance from this source.',
  ai_prompt_injection:
    'Someone planted instructions for AI tools in the logs; a human should review.',
};

function keyFor(f: Finding): string {
  if (f.ip) return `ip:${f.ip}`;
  if (f.user) return `user:${f.user}`;
  return `finding:${f.id}`;
}

function baselineActions(findings: readonly Finding[]): ProposedActionInput[] {
  const seen = new Set<string>();
  const out: ProposedActionInput[] = [];
  for (const f of findings) {
    for (const step of BASELINE[f.detector]) {
      const target = step.on === 'ip' ? f.ip : step.on === 'user' ? f.user : undefined;
      if (step.on && !target) continue;
      const key = `${step.action}:${target ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        action: step.action,
        rationale: BASELINE_REASON[f.detector],
        ...(target ? { target } : {}),
      });
    }
  }
  return out;
}

/**
 * Tactics in the order the attacker reached them (earliest finding first),
 * falling back to ATT&CK matrix order for ties or untimed findings.
 */
export function chronologicalTactics(findings: readonly Finding[]): string[] {
  const firstSeen = new Map<string, number>();
  for (const f of findings) {
    for (const tactic of tacticsFor(f.techniques)) {
      const t = f.firstSeen ?? Number.POSITIVE_INFINITY;
      firstSeen.set(tactic, Math.min(firstSeen.get(tactic) ?? Number.POSITIVE_INFINITY, t));
    }
  }
  const order: readonly string[] = TACTIC_ORDER;
  return [...firstSeen.keys()].sort(
    (a, b) => firstSeen.get(a)! - firstSeen.get(b)! || order.indexOf(a) - order.indexOf(b),
  );
}

function incidentTitle(
  findings: readonly Finding[],
  tactics: readonly string[],
  ips: readonly string[],
): string {
  const lead = findings[0]!;
  if (tactics.length >= 3) {
    const origin = ips[0] ? ` from ${ips[0]}` : '';
    return `Multi-stage intrusion${origin}: ${tactics[0]} → ${tactics[tactics.length - 1]}`;
  }
  return lead.title;
}

export function correlate(findings: readonly Finding[], events: readonly LogEvent[]): Incident[] {
  const uf = new UnionFind();
  const suspiciousIps = new Set(
    findings.map((f) => f.ip).filter((ip): ip is string => Boolean(ip)),
  );

  for (const f of findings) {
    uf.find(keyFor(f));
    if (f.ip && f.user) uf.union(`ip:${f.ip}`, `user:${f.user}`);
  }
  for (const e of events) {
    if (e.kind === 'auth_success' && e.srcIp && e.user && suspiciousIps.has(e.srcIp)) {
      uf.union(`ip:${e.srcIp}`, `user:${e.user}`);
    }
    if (e.kind === 'sudo' && e.user && e.command) {
      const created = ACCOUNT_IN_COMMAND.exec(e.command)?.[1];
      if (created) uf.union(`user:${e.user}`, `user:${created}`);
    }
  }

  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const root = uf.find(keyFor(f));
    const list = groups.get(root);
    if (list) list.push(f);
    else groups.set(root, [f]);
  }

  const incidents = [...groups.values()].map((group) => {
    const sorted = [...group].sort((a, b) => b.score - a.score);
    const techniques = [...new Set(sorted.flatMap((f) => f.techniques))];
    const tactics = chronologicalTactics(sorted);
    const ips = [...new Set(sorted.map((f) => f.ip).filter((x): x is string => Boolean(x)))];
    const users = [...new Set(sorted.map((f) => f.user).filter((x): x is string => Boolean(x)))];
    const top = sorted[0]!.score;
    const score = Math.min(
      100,
      top + Math.min(3, sorted.length - 1) * 2 + Math.max(0, tactics.length - 1) * 3,
    );
    const firsts = sorted.map((f) => f.firstSeen).filter((t): t is number => t !== null);
    const lasts = sorted.map((f) => f.lastSeen).filter((t): t is number => t !== null);
    return {
      title: incidentTitle(sorted, tactics, ips),
      severity: severityFor(score),
      score,
      findingIds: sorted.map((f) => f.id),
      ips,
      users,
      techniques,
      tactics,
      firstSeen: firsts.length ? Math.min(...firsts) : null,
      lastSeen: lasts.length ? Math.max(...lasts) : null,
      baselineActions: baselineActions(sorted),
    };
  });

  return incidents
    .sort((a, b) => b.score - a.score)
    .map((inc, i) => ({ id: `INC-${i + 1}`, ...inc }));
}
