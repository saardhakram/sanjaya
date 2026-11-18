import { techniqueName } from './mitre.js';
import type { AnalysisResult, Incident, IncidentAssessment, ProposedAction } from './types.js';

/** Pure helpers used by the browser UI to order results and export reports. */

export type Decision = 'approved' | 'rejected';

export interface AuditEntry {
  at: string;
  actionId: string;
  decision: Decision;
  analyst: string;
}

export function assessmentFor(
  result: AnalysisResult,
  incidentId: string,
): IncidentAssessment | undefined {
  return result.triage.assessments.find((a) => a.incidentId === incidentId);
}

/** Incidents in AI/analyst priority order, falling back to engine score. */
export function orderedIncidents(result: AnalysisResult): Incident[] {
  const priority = (i: Incident): number =>
    assessmentFor(result, i.id)?.priority ?? Number.MAX_SAFE_INTEGER;
  return [...result.incidents].sort((a, b) => priority(a) - priority(b) || b.score - a.score);
}

export function actionsFor(result: AnalysisResult, incidentId: string): ProposedAction[] {
  return result.actions.filter((a) => a.incidentId === incidentId);
}

export function formatTime(epochMs: number | null): string {
  if (epochMs === null) return 'unknown time';
  return new Date(epochMs).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

/** Latest decision per action, derived from the append-only audit trail. */
export function currentDecisions(audit: readonly AuditEntry[]): Map<string, Decision> {
  const map = new Map<string, Decision>();
  for (const entry of audit) map.set(entry.actionId, entry.decision);
  return map;
}

function cleanAnalyst(name: string): string {
  const trimmed = name
    .replace(/[\r\n]+/g, ' ')
    .trim()
    .slice(0, 60);
  return trimmed || 'unnamed analyst';
}

export function auditEntry(
  actionId: string,
  decision: Decision,
  analyst: string,
  at: Date = new Date(),
): AuditEntry {
  return { at: at.toISOString(), actionId, decision, analyst: cleanAnalyst(analyst) };
}

/** Markdown runbook containing only human-approved actions, plus the full audit trail. */
export function buildRunbook(result: AnalysisResult, audit: readonly AuditEntry[]): string {
  const decisions = currentDecisions(audit);
  const approved = result.actions.filter((a) => decisions.get(a.id) === 'approved');
  const lines: string[] = [
    '# Sanjaya incident response runbook',
    '',
    `Generated: ${new Date().toISOString()}  `,
    `Analysis engine: ${result.meta.engine === 'gemini' ? `Gemini (${result.meta.model ?? 'model'})` : 'rule-based'}  `,
    `Request ID: ${result.meta.requestId}`,
    '',
    '## Summary',
    '',
    result.triage.executiveSummary,
    '',
    '## Incidents',
    '',
  ];
  for (const inc of orderedIncidents(result)) {
    const a = assessmentFor(result, inc.id);
    lines.push(
      `### ${inc.id}: ${inc.title} (${inc.severity.toUpperCase()}, risk ${inc.score}/100)`,
      '',
    );
    if (a)
      lines.push(
        a.assessment,
        '',
        `Attacker objective: ${a.attackerObjective} (confidence: ${a.confidence})`,
        '',
      );
    lines.push(
      `MITRE ATT&CK: ${inc.techniques.map((t) => `${t} ${techniqueName(t)}`).join('; ')}`,
      '',
    );
  }
  lines.push('## Approved actions', '');
  if (approved.length === 0) lines.push('_No actions approved yet._', '');
  approved.forEach((act, i) => {
    lines.push(
      `${i + 1}. **${act.title}**${act.target ? ` — \`${act.target}\`` : ''} (${act.incidentId}, risk: ${act.risk}${act.reversible ? '' : ', not reversible'})`,
      `   - Why: ${act.rationale}`,
      '',
      '```sh',
      act.command,
      '```',
      '',
    );
  });
  lines.push(
    '## Audit trail',
    '',
    '| Time (UTC) | Action | Decision | Analyst |',
    '| --- | --- | --- | --- |',
  );
  for (const e of audit) {
    const act = result.actions.find((x) => x.id === e.actionId);
    const label = act ? `${act.id} ${act.title}`.replace(/\|/g, '/') : e.actionId;
    lines.push(`| ${e.at} | ${label} | ${e.decision} | ${e.analyst.replace(/\|/g, '/')} |`);
  }
  lines.push('', '> Sanjaya never executes commands. Review each step before running it.');
  return lines.join('\n') + '\n';
}

export function countLines(text: string): number {
  return text.split(/\r?\n/).filter((l) => l.trim() !== '').length;
}
