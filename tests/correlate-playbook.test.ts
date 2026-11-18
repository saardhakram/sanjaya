import { describe, expect, it } from 'vitest';
import { materializeActions } from '../src/server/engine/analyze.js';
import { chronologicalTactics } from '../src/server/engine/correlate.js';
import {
  buildAction,
  isValidIp,
  isValidUsername,
  PLAYBOOK_IDS,
} from '../src/server/engine/playbook.js';
import { tacticsFor, techniqueName } from '../src/shared/mitre.js';
import type { Finding } from '../src/shared/types.js';
import { engine } from './helpers.js';

describe('correlation', () => {
  it('merges the whole kill chain into one critical incident', () => {
    const { incidents } = engine('kill-chain');
    const chain = incidents.find((i) => i.ips.includes('203.0.113.45'));
    expect(chain).toBeDefined();
    expect(chain!.severity).toBe('critical');
    expect(chain!.users.sort()).toEqual(['deploy', 'sysupdate']);
    expect(chain!.tactics[0]).toBe('Discovery');
    expect(chain!.tactics.at(-1)).toBe('Persistence');
    expect(chain!.title).toMatch(/^Multi-stage intrusion from 203\.0\.113\.45/);
  });

  it('keeps unrelated attackers in separate incidents', () => {
    const { incidents } = engine('web-attack');
    expect(incidents).toHaveLength(3);
    for (const inc of incidents) expect(inc.ips).toHaveLength(1);
  });

  it('does not link a legitimate admin login to an attacker', () => {
    const { incidents } = engine('ssh-compromise');
    expect(incidents.flatMap((i) => i.users)).not.toContain('alice');
  });

  it('orders tactics by time, with ATT&CK order for ties', () => {
    const base: Omit<Finding, 'techniques' | 'firstSeen' | 'lastSeen'> = {
      id: 'F',
      detector: 'port_scan',
      title: '',
      severity: 'low',
      score: 1,
      count: 1,
      evidence: [],
      details: '',
    };
    const findings: Finding[] = [
      { ...base, techniques: ['T1078'], firstSeen: 200, lastSeen: 200 },
      { ...base, techniques: ['T1046'], firstSeen: 100, lastSeen: 100 },
      { ...base, techniques: ['T1595.002'], firstSeen: null, lastSeen: null },
    ];
    expect(chronologicalTactics(findings)).toEqual([
      'Discovery',
      'Initial Access',
      'Reconnaissance',
    ]);
  });

  it('proposes baseline actions with validated targets', () => {
    const { incidents } = engine('ssh-compromise');
    const actions = incidents[0]!.baselineActions.map((a) => a.action);
    expect(actions).toEqual(
      expect.arrayContaining(['lock_account', 'block_ip', 'remove_unauthorized_account']),
    );
  });
});

describe('MITRE helpers', () => {
  it('names known techniques and passes through unknown ones', () => {
    expect(techniqueName('T1046')).toBe('Network Service Discovery');
    expect(techniqueName('T9999')).toBe('T9999');
    expect(tacticsFor(['T9999', 'T1046', 'T1595.002'])).toEqual(['Reconnaissance', 'Discovery']);
  });
});

describe('playbook safety', () => {
  it('validates IPs and usernames strictly', () => {
    expect(isValidIp('203.0.113.45')).toBe(true);
    expect(isValidIp('2001:db8::1')).toBe(true);
    expect(isValidIp('256.1.1.1')).toBe(false);
    expect(isValidIp('1.2.3.4; rm -rf /')).toBe(false);
    expect(isValidUsername('deploy')).toBe(true);
    expect(isValidUsername('x;rm -rf /')).toBe(false);
    expect(isValidUsername('$(reboot)')).toBe(false);
  });

  it('refuses to build commands with unsafe or missing targets', () => {
    expect(buildAction('A', 'INC-1', 'lock_account', 'r', 'bob`id`')).toBeNull();
    expect(buildAction('A', 'INC-1', 'block_ip', 'r')).toBeNull();
    expect(buildAction('A', 'INC-1', 'block_ip', 'r', '203.0.113.5')?.command).toBe(
      'sudo ufw insert 1 deny from 203.0.113.5 to any',
    );
  });

  it('ignores targets for actions that take none and truncates rationale', () => {
    const a = buildAction('A', 'INC-1', 'rate_limit_ssh', 'x'.repeat(1000), 'whatever');
    expect(a?.target).toBeUndefined();
    expect(a?.rationale).toHaveLength(400);
  });

  it('builds a command for every playbook entry', () => {
    for (const id of PLAYBOOK_IDS) {
      const a = buildAction(
        'A',
        'I',
        id,
        'r',
        id === 'block_ip' || id === 'add_waf_rule' ? '192.0.2.1' : 'bob',
      );
      expect(a?.command.length).toBeGreaterThan(5);
    }
  });

  it('dedupes and drops invalid actions when materializing', () => {
    const actions = materializeActions([
      {
        incidentId: 'INC-1',
        actions: [
          { action: 'block_ip', target: '192.0.2.1', rationale: 'a' },
          { action: 'block_ip', target: '192.0.2.1', rationale: 'dup' },
          { action: 'lock_account', target: 'bad user', rationale: 'b' },
          { action: 'escalate_to_human', rationale: 'c' },
        ],
      },
    ]);
    expect(actions.map((a) => `${a.id}:${a.action}`)).toEqual([
      'ACT-1:block_ip',
      'ACT-2:escalate_to_human',
    ]);
  });
});
