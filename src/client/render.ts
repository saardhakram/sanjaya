import { techniqueName } from '../shared/mitre.js';
import {
  actionsFor,
  assessmentFor,
  currentDecisions,
  formatTime,
  orderedIncidents,
  type AuditEntry,
} from '../shared/report.js';
import type {
  AnalysisResult,
  DrishtiEntity,
  DrishtiReport,
  Finding,
  Incident,
  ProposedAction,
} from '../shared/types.js';
import { h } from './dom.js';

export interface Handlers {
  onDecide: (action: ProposedAction, decision: 'approved' | 'rejected') => void;
  onExportRunbook: () => void;
  onExportJson: () => void;
  onAnalystChange: (name: string) => void;
}

const nf = new Intl.NumberFormat('en');
const SVG_NS = 'http://www.w3.org/2000/svg';

function capitalise(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** The shared chakra emblem (defined once in index.html). */
export function chakra(): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 100 100');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#chakra');
  svg.append(use);
  return svg;
}

/** Concentric rings: stage n of the attack is drawn n rings deep, like the Chakravyuha. */
function rings(depth: number): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < depth; i++) {
    const c = document.createElementNS(SVG_NS, 'circle');
    c.setAttribute('cx', '12');
    c.setAttribute('cy', '12');
    c.setAttribute('r', String(11 - i * 2.2));
    svg.append(c);
  }
  return svg;
}

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
  const secs = `${(m.durationMs / 1000).toFixed(1)} s`;
  if (m.cached) return `Served from memory in ${secs}, with no new tokens used.`;
  if (m.engine !== 'gemini') return `Read by the rule engine in ${secs}.`;
  const turns = `${m.agentTurns} turn${m.agentTurns === 1 ? '' : 's'}`;
  const tokens = nf.format(m.tokens.input + m.tokens.output);
  return `Investigated by ${m.model ?? 'Gemini'} in ${secs}: ${turns}, ${m.toolCalls} tool calls, ${tokens} tokens.`;
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
    const more = finding.count - finding.evidence.length;
    pre.append('\n', h('span', { class: 'ln' }, `… ${more} more matching lines`));
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
      h('span', { class: `badge ${finding.severity}` }, capitalise(finding.severity)),
      h('span', { class: 'inc-id' }, finding.id),
      finding.title,
      finding.detector === 'ml_anomaly' && h('span', { class: 'ml-tag' }, 'Found by ML'),
    ),
    h(
      'div',
      { class: 'finding-body' },
      h('p', {}, finding.details),
      h(
        'p',
        { class: 'muted' },
        `${formatTime(finding.firstSeen)} to ${formatTime(finding.lastSeen)}, ${finding.count} event(s)`,
      ),
      evidenceBlock(finding, lines),
    ),
  );
}

function riskBadgeClass(action: ProposedAction): string {
  if (action.risk === 'high') return 'critical';
  return action.risk === 'medium' ? 'medium' : 'low';
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
  const state = h(
    'span',
    { class: 'decision-state', 'data-role': 'state' },
    'Awaiting your decision',
  );
  const titleId = `${action.id}-title`;
  approve.setAttribute('aria-describedby', titleId);
  reject.setAttribute('aria-describedby', titleId);

  let confirming = false;
  const resetApprove = (): void => {
    confirming = false;
    approve.textContent = 'Approve';
    approve.classList.remove('confirm');
  };
  approve.addEventListener('click', () => {
    if (action.risk === 'high' && !confirming && approve.getAttribute('aria-pressed') !== 'true') {
      confirming = true;
      approve.textContent = 'Confirm: this cannot be undone';
      approve.classList.add('confirm');
      return;
    }
    resetApprove();
    handlers.onDecide(action, 'approved');
  });
  reject.addEventListener('click', () => {
    resetApprove();
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
      h('span', { class: `badge ${riskBadgeClass(action)}` }, `${capitalise(action.risk)} risk`),
    ),
    h(
      'p',
      { class: 'action-meta' },
      `${action.id}, ${action.reversible ? 'can be undone' : 'cannot be undone'}`,
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

function vyuha(incident: Incident): HTMLElement {
  const labelId = `${incident.id}-vyuha`;
  return h(
    'div',
    { class: 'vyuha' },
    h(
      'p',
      { class: 'vyuha-label', id: labelId },
      h('strong', {}, 'Chakravyuha'),
      ': how deep the attacker went, stage by stage',
    ),
    h(
      'ol',
      { class: 'chain', 'aria-labelledby': labelId },
      incident.tactics.map((t, i) => h('li', {}, rings(Math.min(5, i + 1)), t)),
    ),
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
        h('span', { class: `badge ${incident.severity}` }, capitalise(incident.severity)),
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
        a ? `Priority ${a.priority}, risk ` : 'Risk ',
        h('strong', {}, String(incident.score)),
        '/100',
      ),
    ),
    incident.tactics.length > 0 && vyuha(incident),
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
        h('dt', {}, 'Attacker’s aim'),
        h('dd', {}, a.attackerObjective),
        h('dt', {}, 'Confidence'),
        h('dd', {}, capitalise(a.confidence)),
        h('dt', {}, 'Verdict'),
        h('dd', {}, a.likelyTruePositive ? 'Likely a real attack' : 'Possibly harmless; verify'),
        h('dt', {}, 'When'),
        h('dd', {}, `${formatTime(incident.firstSeen)} to ${formatTime(incident.lastSeen)}`),
      ),
    h('h4', { class: 'subhead' }, 'MITRE ATT&CK techniques'),
    h(
      'ul',
      { class: 'techniques' },
      incident.techniques.map((t) => h('li', {}, h('code', {}, t), ` ${techniqueName(t)}`)),
    ),
    h('h4', { class: 'subhead' }, `Evidence (${findings.length} findings)`),
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

function ledgerCard(handlers: Handlers, analyst: string): HTMLElement {
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
    { class: 'card ledger', 'aria-labelledby': 'ledger-title' },
    h('h3', { id: 'ledger-title' }, 'Chitragupta’s ledger'),
    h(
      'p',
      { class: 'muted small' },
      'Like Chitragupta, who records every deed, this ledger records every approval and rejection. Sanjaya never runs a command itself: approved steps become a runbook for you to run.',
    ),
    h(
      'div',
      { class: 'runbook-controls' },
      h('div', { class: 'field' }, h('label', { for: 'analyst' }, 'Your name'), nameInput),
      exportMd,
      exportJson,
    ),
    h(
      'p',
      { id: 'approved-count', class: 'decision-state', 'aria-live': 'polite' },
      '0 actions approved',
    ),
    h('ul', { id: 'audit', class: 'audit', 'aria-label': 'Ledger entries' }),
  );
}

/** Shown entities before the rest are summarised. */
const DRISHTI_ROWS = 8;

function drishtiTag(e: DrishtiEntity): HTMLElement {
  if (!e.anomalous) return h('span', { class: 'd-tag normal' }, 'Normal');
  return e.ruleFlagged
    ? h('span', { class: 'd-tag agree' }, 'Rules agree')
    : h('span', { class: 'd-tag missed' }, 'Rules missed this');
}

function drishtiRow(e: DrishtiEntity): HTMLElement {
  const state = !e.anomalous ? 'normal' : e.ruleFlagged ? 'agree' : 'missed';
  const fill = h('span', { class: 'd-fill' });
  // CSSOM, not a style attribute: the CSP forbids inline styles.
  fill.style.width = `${e.score}%`;
  return h(
    'li',
    { class: `d-row ${state}` },
    h('span', { class: 'd-ip' }, e.ip),
    h(
      'span',
      { class: 'd-bar', role: 'img', 'aria-label': `Anomaly score ${e.score} of 100` },
      fill,
    ),
    h('span', { class: 'd-score' }, String(e.score)),
    drishtiTag(e),
    e.anomalous &&
      e.reasons.length > 0 &&
      h(
        'ul',
        { class: 'd-reasons' },
        e.reasons.map((r) =>
          h('li', {}, `${r.label}: `, h('strong', {}, r.value), `, normally ${r.typical}`),
        ),
      ),
  );
}

function drishtiCard(report: DrishtiReport): HTMLElement {
  const missed = report.entities.filter((e) => e.anomalous && !e.ruleFlagged).length;
  const summary =
    report.flagged === 0
      ? `Every one of the ${report.entities.length} IPs behaves like normal traffic.`
      : `${report.flagged} of ${report.entities.length} IPs behave unusually` +
        (missed > 0
          ? `, and ${missed} of them slipped past every rule.`
          : ', and the rules caught all of them too.');
  const shown = report.entities.slice(0, DRISHTI_ROWS);
  const rest = report.entities.length - shown.length;
  return h(
    'section',
    { class: `card drishti ${missed > 0 ? 'has-missed' : ''}`, 'aria-labelledby': 'drishti-title' },
    h(
      'div',
      { class: 'drishti-head' },
      h('span', { class: 'drishti-deva', lang: 'sa' }, 'दृष्टि'),
      h('h3', { id: 'drishti-title' }, 'Drishti, the third eye'),
      h('span', { class: 'ai-badge ml' }, 'Machine learning'),
    ),
    h(
      'p',
      { class: 'muted small' },
      `An anomaly-detection model (Isolation Forest) that learned how ${nf.format(report.trainingProfiles)} normal clients behave. ` +
        'It scores every IP on how unusual it is, so it can spot attacks no rule describes. 50 or more is flagged.',
    ),
    h('p', { class: 'drishti-summary' }, summary),
    shown.length > 0 &&
      h('ul', { class: 'd-list', 'aria-label': 'Anomaly score per IP' }, shown.map(drishtiRow)),
    rest > 0 && h('p', { class: 'muted small' }, `${rest} more IP(s) scored lower.`),
  );
}

function narration(result: AnalysisResult): HTMLElement {
  const s = result.stats;
  const engineBadge =
    result.meta.engine === 'gemini'
      ? h('span', { class: 'ai-badge' }, 'Gemini analyst')
      : h('span', { class: 'ai-badge rules' }, 'Rule engine');
  return h(
    'section',
    { class: `card narration ${s.incidents === 0 ? 'clean' : ''}`, 'aria-labelledby': 'uvacha' },
    h(
      'p',
      { class: 'narration-head' },
      h('span', { class: 'uvacha', lang: 'sa', id: 'uvacha' }, 'सञ्जय उवाच'),
      h('span', { class: 'uvacha-en' }, 'Sanjaya said'),
      engineBadge,
    ),
    h('p', { class: 'summary-text' }, result.triage.executiveSummary),
    result.meta.fallbackReason &&
      result.incidents.length > 0 &&
      h('p', { class: 'notes' }, result.meta.fallbackReason),
    result.triage.analystNotes &&
      result.meta.engine === 'gemini' &&
      h('p', { class: 'notes' }, result.triage.analystNotes),
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
  const report = h(
    'div',
    { class: 'report' },
    h(
      'div',
      { class: 'result-head' },
      h('h2', { id: 'report-heading', tabindex: -1 }, 'What Sanjaya saw'),
      h('p', { class: 'meta' }, metaLine(result)),
    ),
    h(
      'ul',
      { class: 'tiles', 'aria-label': 'Summary figures' },
      tile(nf.format(s.linesParsed), `of ${nf.format(s.linesTotal)} lines understood`),
      tile(s.findings, 'findings'),
      tile(s.incidents, 'incidents'),
      tile(s.critical, 'critical', s.critical > 0 ? 'crit' : ''),
    ),
    narration(result),
    result.drishti.entities.length > 0 && drishtiCard(result.drishti),
    orderedIncidents(result).map((inc) => incidentCard(result, inc, lines, handlers)),
    result.actions.length > 0 && ledgerCard(handlers, analyst),
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
        d === 'approved' ? 'Approved' : d === 'rejected' ? 'Rejected' : 'Awaiting your decision';
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
        const what = act ? ` (${act.title}${act.target ? `: ${act.target}` : ''})` : '';
        return h(
          'li',
          {},
          h('time', { datetime: e.at }, e.at.slice(11, 19)),
          `${e.analyst} ${e.decision} ${e.actionId}${what}`,
        );
      }),
    );
  }
}
