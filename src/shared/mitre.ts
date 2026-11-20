/**
 * The subset of MITRE ATT&CK (and MITRE ATLAS for AI attacks) that the
 * detectors map to. Kept local so mappings are deterministic and offline.
 */

export interface Technique {
  id: string;
  name: string;
  tactic: string;
}

/** ATT&CK enterprise tactics in kill-chain order. */
export const TACTIC_ORDER = [
  'Reconnaissance',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Impact',
] as const;

export const TECHNIQUES: Readonly<Record<string, Technique>> = {
  'T1595.002': {
    id: 'T1595.002',
    name: 'Active Scanning: Vulnerability Scanning',
    tactic: 'Reconnaissance',
  },
  'T1595.003': {
    id: 'T1595.003',
    name: 'Active Scanning: Wordlist Scanning',
    tactic: 'Reconnaissance',
  },
  T1046: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  T1119: { id: 'T1119', name: 'Automated Collection', tactic: 'Collection' },
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  'T1110.001': {
    id: 'T1110.001',
    name: 'Brute Force: Password Guessing',
    tactic: 'Credential Access',
  },
  'T1110.003': {
    id: 'T1110.003',
    name: 'Brute Force: Password Spraying',
    tactic: 'Credential Access',
  },
  T1078: { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
  'T1548.003': {
    id: 'T1548.003',
    name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
    tactic: 'Privilege Escalation',
  },
  'T1136.001': {
    id: 'T1136.001',
    name: 'Create Account: Local Account',
    tactic: 'Persistence',
  },
  'T1098.007': {
    id: 'T1098.007',
    name: 'Account Manipulation: Additional Local or Domain Groups',
    tactic: 'Persistence',
  },
  'T1059.004': {
    id: 'T1059.004',
    name: 'Command and Scripting Interpreter: Unix Shell',
    tactic: 'Execution',
  },
  'AML.T0051': {
    id: 'AML.T0051',
    name: 'LLM Prompt Injection (MITRE ATLAS)',
    tactic: 'Defense Evasion',
  },
};

export function techniqueName(id: string): string {
  return TECHNIQUES[id]?.name ?? id;
}

/** Distinct tactics for a set of techniques, sorted in kill-chain order. */
export function tacticsFor(techniqueIds: readonly string[]): string[] {
  const set = new Set<string>();
  for (const id of techniqueIds) {
    const tactic = TECHNIQUES[id]?.tactic;
    if (tactic) set.add(tactic);
  }
  const order: readonly string[] = TACTIC_ORDER;
  return [...set].sort((a, b) => order.indexOf(a) - order.indexOf(b));
}
