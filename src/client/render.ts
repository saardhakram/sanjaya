import { techniqueName } from '../shared/mitre.js';
import {
  actionsFor,
  assessmentFor,
  currentDecisions,
  formatTime,
  orderedIncidents,
  type AuditEntry,
} from '../shared/report.js';
import type { AnalysisResult, Finding, Incident, ProposedAction } from '../shared/types.js';
import { h } from './dom.js';

export interface Handlers {
  onDecide: (action: ProposedAction, decision: 'approved' | 'rejected') => void;
  onExportRunbook: () => void;
  onExportJson: () => void;
  onAnalystChange: (name: string) => void;
}

const nf = new Intl.NumberFormat('en');

function tile(value: number | string, label: string, extra = ''): HTMLElement {
  return h(
    'li',
    { class: `tile ${extra}` },
    h('span', { class: 'tile-value' }, String(value)),
    h('span', { class: 'tile-label' }, label),
  );
}

function metaLine(result: AnalysisResult): string {
  const m = result.meta;
  const parts: string[] = [];
  if (m.engine === 'gemini') {
    parts.push(`Investigated by ${m.model ?? 'Gemini'}`);
    parts.push(`${m.agentTurns} agent turn${m.agentTurns === 1 ? '' : 's'}`);
    parts.push(`${m.toolCalls} tool calls`);
    parts.push(`${nf.format(m.tokens.input + m.tokens.output)} tokens`);
  } else {
    parts.push('Rule-based triage');
  }
  if (m.cached) parts.push('served from cache (0 new tokens)');
  parts.push(`${(m.durationMs / 1000).toFixed(1)} s`);
  return parts.join(' · ');
}

function evidenceBlock(finding: Finding, lines: readonly string[]): HTMLElement {
  const pre = h('pre', {
    class: 'evidence',
    tabindex: 0,
    'aria-label': `Evidence for ${finding.id}`,
  });
  finding.evidence.forEach((n, i) => {
    if (i > 0) pre.append('\n');
    pre.append(h('span', { class: 'ln' }, `${String(n).padStart(4, ' ')}  `), lines[n - 1] ?? '');
  });
  if (finding.count > finding.evidence.length) {
    pre.append(
      '\n',
      h(
        'span',
        { class: 'ln' },
        `… ${finding.count - finding.evidence.length} more matching lines`,
      ),
    );
  }
  return pre;
}

function findingDetails(finding: Finding, lines: readonly string[]): HTMLElement {
  return h(
    'details',
    { class: 'finding' },
    h(
      'summary',
      {},
      h('span', { class: `badge ${finding.severity}` }, finding.severity),
      h('span', { class: 'inc-id' }, finding.id),
      finding.title,
    ),
    h(
      'div',
      { class: 'finding-body' },
      h('p', {}, finding.details),
      h(
        'p',
        { class: 'muted' },
        `${formatTime(finding.firstSeen)} → ${formatTime(finding.lastSeen)} · ${finding.count} event(s)`,
      ),
      evidenceBlock(finding, lines),
    ),
  );
}

function actionItem(action: ProposedAction, handlers: Handlers): HTMLElement {
  const approve = h(
    'button',
    {
      class: 'btn btn-sm approve',
      type: 'button',
      'aria-pressed': 'false',
      'data-role': 'approve',
    },
    'Approve',
  );
  const reject = h(
    'button',
    { class: 'btn btn-sm reject', type: 'button', 'aria-pressed': 'false', 'data-role': 'reject' },
    'Reject',
  );
  const state = h('span', { class: 'decision-state', 'data-role': 'state' }, 'Awaiting decision');
  const titleId = `${action.id}-title`;
  approve.setAttribute('aria-describedby', titleId);
  reject.setAttribute('aria-describedby', titleId);

  let confirming = false;
  approve.addEventListener('click', () => {
    if (action.risk === 'high' && !confirming && approve.getAttribute('aria-pressed') !== 'true') {
      confirming = true;
      approve.textContent = 'Confirm approval (high risk)';
      approve.classList.add('confirm');
      return;
    }
    confirming = false;
    approve.textContent = 'Approve';
    approve.classList.remove('confirm');
    handlers.onDecide(action, 'approved');
  });
  reject.addEventListener('click', () => {
    confirming = false;
    approve.textContent = 'Approve';
    approve.classList.remove('confirm');
    handlers.onDecide(action, 'rejected');
  });

  return h(
    'li',
    { class: 'action', 'data-action-id': action.id },
    h(
      'div',
      { class: 'action-head' },
      h(
        'p',
        { class: 'action-title', id: titleId },
        `${action.title}${action.target ? `: ${action.target}` : ''}`,
      ),
      h(
        'span',
        {
          class: `badge ${action.risk === 'high' ? 'critical' : action.risk === 'medium' ? 'medium' : 'low'}`,
        },
        `${action.risk} risk`,
      ),
    ),
    h(
      'p',
      { class: 'action-meta' },
      `${action.id} · ${action.reversible ? 'reversible' : 'not reversible'}`,
    ),
    h('p', { class: 'action-why' }, action.rationale),
    h(
      'pre',
      { class: 'cmd', tabindex: 0, 'aria-label': `Suggested command for ${action.id}` },
      action.command,
    ),
    h('div', { class: 'decision' }, approve, reject, state),
  );
}

function incidentCard(
  result: AnalysisResult,
  incident: Incident,
  lines: readonly string[],
  handlers: Handlers,
): HTMLElement {
  const a = assessmentFor(result, incident.id);
  const findings = result.findings.filter((f) => incident.findingIds.includes(f.id));
  const actions = actionsFor(result, incident.id);
  const headingId = `${incident.id}-heading`;

  return h(
    'article',
    { class: `card incident sev-${incident.severity}`, 'aria-labelledby': headingId },
    h(
      'div',
      { class: 'incident-head' },
      h(
        'div',
        { class: 'incident-title' },
        h('span', { class: `badge ${incident.severity}` }, incident.severity),
        h(
          'h3',
          { id: headingId },
          h('span', { class: 'inc-id' }, `${incident.id} `),
          incident.title,
        ),
      ),
      h(
        'span',
        { class: 'score' },
        a ? `Priority ${a.priority} · ` : '',
        `Risk ${incident.score}/100`,
      ),
    ),
    incident.tactics.length > 0 &&
      h(
        'ol',
        { class: 'chain', 'aria-label': 'Attack stages in the order observed' },
        incident.tactics.map((t) => h('li', {}, t)),
      ),
    h(
      'ul',
      { class: 'entities', 'aria-label': 'Involved IPs and accounts' },
      incident.ips.map((ip) => h('li', { class: 'entity' }, `ip ${ip}`)),
      incident.users.map((u) => h('li', { class: 'entity' }, `user ${u}`)),
    ),
    a && h('p', { class: 'assessment' }, a.assessment),
    a &&
      h(
        'dl',
        { class: 'facts' },
        h('dt', {}, 'Attacker objective'),
        h('dd', {}, a.attackerObjective),
        h('dt', {}, 'Confidence'),
        h('dd', {}, a.confidence),
        h('dt', {}, 'Verdict'),
        h('dd', {}, a.likelyTruePositive ? 'Likely true positive' : 'Possibly benign; verify'),
        h('dt', {}, 'Timeframe'),
        h('dd', {}, `${formatTime(incident.firstSeen)} → ${formatTime(incident.lastSeen)}`),
      ),
    h('h4', { class: 'subhead' }, 'MITRE ATT&CK techniques'),
    h(
      'ul',
      { class: 'techniques' },
      incident.techniques.map((t) => h('li', {}, h('code', {}, t), ` ${techniqueName(t)}`)),
    ),
    h('h4', { class: 'subhead' }, `Findings and evidence (${findings.length})`),
    findings.map((f) => findingDetails(f, lines)),
    h('h4', { class: 'subhead' }, `Proposed response (${actions.length})`),
    actions.length > 0
      ? h(
          'ul',
          { class: 'actions' },
          actions.map((act) => actionItem(act, handlers)),
        )
      : h('p', { class: 'muted' }, 'No playbook action proposed.'),
  );
}

function runbookCard(handlers: Handlers, analyst: string): HTMLElement {
  const nameInput = h('input', {
    id: 'analyst',
    type: 'text',
    value: analyst,
    autocomplete: 'name',
    maxlength: 60,
  });
  nameInput.addEventListener('input', () => handlers.onAnalystChange(nameInput.value));
  const exportMd = h('button', { class: 'btn btn-sm', type: 'button' }, 'Download runbook (.md)');
  const exportJson = h(
    'button',
    { class: 'btn btn-sm', type: 'button' },
    'Download full report (.json)',
  );
  exportMd.addEventListener('click', handlers.onExportRunbook);
  exportJson.addEventListener('click', handlers.onExportJson);
  return h(
    'section',
    { class: 'card', 'aria-labelledby': 'runbook-title' },
    h('p', { class: 'card-label' }, 'Human oversight'),
    h('h3', { id: 'runbook-title' }, 'Response runbook and audit trail'),
    h(
      'p',
      { class: 'muted small' },
      'Sanjaya never runs commands. Approved steps go into a runbook you can review and run, and every decision is logged.',
    ),
    h(
      'div',
      { class: 'runbook-controls' },
      h('div', { class: 'field' }, h('label', { for: 'analyst' }, 'Approving analyst'), nameInput),
      exportMd,
      exportJson,
    ),
    h(
      'p',
      { id: 'approved-count', class: 'decision-state', 'aria-live': 'polite' },
      '0 actions approved',
    ),
    h('ul', { id: 'audit', class: 'audit', 'aria-label': 'Audit trail' }),
  );
}

export function renderResults(
  root: HTMLElement,
  result: AnalysisResult,
  logText: string,
  analyst: string,
  handlers: Handlers,
): void {
  const lines = logText.split(/\r?\n/);
  const s = result.stats;
  const engineBadge =
    result.meta.engine === 'gemini'
      ? h('span', { class: 'ai-badge' }, 'Gemini analyst')
      : h('span', { class: 'ai-badge rules' }, 'Rule-based');

  const report = h(
    'div',
    { class: 'report' },
    h(
      'div',
      { class: 'result-head' },
      h('h2', { id: 'report-heading', tabindex: -1 }, 'Triage report'),
      h('p', { class: 'meta' }, metaLine(result)),
    ),
    h(
      'ul',
      { class: 'tiles', 'aria-label': 'Summary figures' },
      tile(nf.format(s.linesParsed), `of ${nf.format(s.linesTotal)} lines parsed`),
      tile(s.findings, 'findings'),
      tile(s.incidents, 'incidents'),
      tile(s.critical, 'critical incidents', s.critical > 0 ? 'crit' : ''),
    ),
    h(
      'section',
      { class: `card ${s.incidents === 0 ? 'clean' : ''}`, 'aria-labelledby': 'summary-title' },
      h(
        'p',
        { class: 'card-label' },
        h('span', { id: 'summary-title' }, 'Executive summary'),
        engineBadge,
      ),
      h('p', { class: 'summary-text' }, result.triage.executiveSummary),
      result.meta.fallbackReason &&
        result.incidents.length > 0 &&
        h('p', { class: 'notes' }, result.meta.fallbackReason),
      result.triage.analystNotes &&
        result.meta.engine === 'gemini' &&
        h('p', { class: 'notes' }, result.triage.analystNotes),
    ),
    orderedIncidents(result).map((inc) => incidentCard(result, inc, lines, handlers)),
    result.actions.length > 0 && runbookCard(handlers, analyst),
  );
  root.replaceChildren(report);
}

/** Updates decision state in place so focus and open <details> are preserved. */
export function renderDecisions(
  root: HTMLElement,
  result: AnalysisResult,
  audit: readonly AuditEntry[],
): void {
  const decisions = currentDecisions(audit);
  for (const item of root.querySelectorAll<HTMLElement>('[data-action-id]')) {
    const id = item.dataset.actionId ?? '';
    const d = decisions.get(id);
    item.classList.toggle('is-approved', d === 'approved');
    item.classList.toggle('is-rejected', d === 'rejected');
    item
      .querySelector('[data-role=approve]')
      ?.setAttribute('aria-pressed', String(d === 'approved'));
    item
      .querySelector('[data-role=reject]')
      ?.setAttribute('aria-pressed', String(d === 'rejected'));
    const state = item.querySelector<HTMLElement>('[data-role=state]');
    if (state) {
      state.textContent =
        d === 'approved' ? 'Approved' : d === 'rejected' ? 'Rejected' : 'Awaiting decision';
      state.className = `decision-state ${d ?? ''}`;
    }
  }
  const approved = [...decisions.values()].filter((d) => d === 'approved').length;
  const count = root.querySelector('#approved-count');
  if (count) count.textContent = `${approved} of ${result.actions.length} actions approved`;
  const list = root.querySelector('#audit');
  if (list) {
    list.replaceChildren(
      ...[...audit].reverse().map((e) => {
        const act = result.actions.find((x) => x.id === e.actionId);
        return h(
          'li',
          {},
          h('time', { datetime: e.at }, e.at.slice(11, 19)),
          `${e.analyst} ${e.decision} ${e.actionId}${act ? ` (${act.title}${act.target ? `: ${act.target}` : ''})` : ''}`,
        );
      }),
    );
  }
}
