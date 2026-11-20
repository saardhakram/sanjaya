/**
 * Types shared by the server (engine + API) and the browser client.
 * Everything numeric in a report (scores, counts, severities) is produced by
 * deterministic, tested code. The AI analyst only adds narrative, priority and
 * a choice of actions from a fixed playbook.
 */

export type LogSource = 'auth' | 'web' | 'firewall' | 'unknown';

export type EventKind =
  | 'auth_failure'
  | 'auth_success'
  | 'invalid_user'
  | 'sudo'
  | 'account_created'
  | 'group_change'
  | 'http_request'
  | 'firewall_block'
  | 'firewall_allow'
  | 'other';

export interface LogEvent {
  /** 1-based line number in the submitted log text. */
  line: number;
  raw: string;
  source: LogSource;
  kind: EventKind;
  /** Epoch milliseconds, or null when the line has no parseable timestamp. */
  timestamp: number | null;
  host?: string;
  srcIp?: string;
  user?: string;
  dstPort?: number;
  method?: string;
  path?: string;
  status?: number;
  userAgent?: string;
  command?: string;
  targetUser?: string;
  group?: string;
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type DetectorId =
  | 'ssh_bruteforce'
  | 'password_spray'
  | 'bruteforce_success'
  | 'privilege_escalation'
  | 'account_persistence'
  | 'port_scan'
  | 'web_attack'
  | 'web_scanner'
  | 'web_enumeration'
  | 'ai_prompt_injection'
  | 'ml_anomaly';

export interface Finding {
  id: string;
  detector: DetectorId;
  title: string;
  severity: Severity;
  score: number;
  techniques: string[];
  ip?: string;
  user?: string;
  firstSeen: number | null;
  lastSeen: number | null;
  count: number;
  /** Line numbers of supporting evidence (capped). */
  evidence: number[];
  details: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  score: number;
  findingIds: string[];
  ips: string[];
  users: string[];
  techniques: string[];
  /** MITRE ATT&CK tactics observed, in kill-chain order. */
  tactics: string[];
  firstSeen: number | null;
  lastSeen: number | null;
  /** Baseline response chosen by rules; the AI may refine it from the same playbook. */
  baselineActions: ProposedActionInput[];
}

export type PlaybookActionId =
  | 'block_ip'
  | 'rate_limit_ssh'
  | 'disable_password_auth'
  | 'lock_account'
  | 'terminate_sessions'
  | 'force_password_reset'
  | 'remove_unauthorized_account'
  | 'review_sudoers'
  | 'add_waf_rule'
  | 'patch_web_app'
  | 'preserve_evidence'
  | 'escalate_to_human';

export type ActionRisk = 'low' | 'medium' | 'high';

export interface ProposedActionInput {
  action: PlaybookActionId;
  target?: string;
  rationale: string;
}

export interface ProposedAction {
  id: string;
  incidentId: string;
  action: PlaybookActionId;
  title: string;
  target?: string;
  rationale: string;
  /** Suggested command, generated from a fixed template with a validated target. Never executed by Sanjaya. */
  command: string;
  risk: ActionRisk;
  reversible: boolean;
}

export type Confidence = 'low' | 'medium' | 'high';

export interface IncidentAssessment {
  incidentId: string;
  priority: number;
  assessment: string;
  attackerObjective: string;
  confidence: Confidence;
  likelyTruePositive: boolean;
}

export interface TriageReport {
  executiveSummary: string;
  assessments: IncidentAssessment[];
  analystNotes: string;
}

export type DrishtiGroup = 'auth' | 'web' | 'network';

export interface DrishtiReason {
  feature: string;
  label: string;
  value: string;
  /** What 95% of normal clients stay at or below. */
  typical: string;
  group: DrishtiGroup;
}

/** Drishti's verdict on one source IP. */
export interface DrishtiEntity {
  ip: string;
  /** 0–100; 50 is the flagging threshold. */
  score: number;
  anomalous: boolean;
  /** True when a deterministic rule already flagged this IP. */
  ruleFlagged: boolean;
  events: number;
  groups: DrishtiGroup[];
  reasons: DrishtiReason[];
}

/** Output of Drishti, the unsupervised anomaly model ("the third eye"). */
export interface DrishtiReport {
  model: string;
  trainingProfiles: number;
  trees: number;
  /** Every scored IP, most anomalous first. */
  entities: DrishtiEntity[];
  flagged: number;
  /** Anomalous IPs no rule caught, each turned into an ml_anomaly finding. */
  newFindings: number;
}

export interface AnalysisStats {
  linesTotal: number;
  linesParsed: number;
  bySource: Record<LogSource, number>;
  findings: number;
  incidents: number;
  critical: number;
  high: number;
}

export interface AnalysisMeta {
  engine: 'gemini' | 'rules';
  model?: string;
  fallbackReason?: string;
  tokens: { input: number; output: number };
  agentTurns: number;
  toolCalls: number;
  cached: boolean;
  durationMs: number;
  requestId: string;
}

export interface AnalysisResult {
  stats: AnalysisStats;
  findings: Finding[];
  incidents: Incident[];
  actions: ProposedAction[];
  triage: TriageReport;
  drishti: DrishtiReport;
  meta: AnalysisMeta;
}
