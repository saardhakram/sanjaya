import { auditEntry, buildRunbook, countLines, type AuditEntry } from '../shared/report.js';
import { SAMPLES } from '../shared/samples.js';
import type { AnalysisResult } from '../shared/types.js';
import { analyze, fetchStatus } from './api.js';
import { byId, download, h } from './dom.js';
import { chakra, renderDecisions, renderResults, type Handlers } from './render.js';

const MAX_BYTES = 256 * 1024;

const form = byId<HTMLFormElement>('analyze-form');
const textarea = byId<HTMLTextAreaElement>('logs');
const fileInput = byId<HTMLInputElement>('file');
const useAi = byId<HTMLInputElement>('use-ai');
const button = byId<HTMLButtonElement>('analyze-btn');
const formError = byId<HTMLParagraphElement>('form-error');
const lineCount = byId<HTMLSpanElement>('log-count');
const results = byId<HTMLDivElement>('results');
const status = byId<HTMLDivElement>('status');
const aiStatus = byId<HTMLParagraphElement>('ai-status');
const sampleList = byId<HTMLDivElement>('sample-list');

/** The introduction shown before the first analysis, restored if one fails. */
const hero = results.firstElementChild?.cloneNode(true) ?? document.createTextNode('');

let current: { result: AnalysisResult; logs: string } | null = null;
let audit: AuditEntry[] = [];
let analyst = '';
let inflight: AbortController | null = null;

function showError(message: string | null): void {
  formError.hidden = message === null;
  formError.textContent = message ?? '';
}

function updateCount(): void {
  const n = countLines(textarea.value);
  lineCount.textContent = `${n.toLocaleString('en')} line${n === 1 ? '' : 's'}`;
}

function selectSample(id: string | null): void {
  for (const btn of sampleList.querySelectorAll<HTMLButtonElement>('button')) {
    btn.setAttribute('aria-pressed', String(btn.dataset.sample === id));
  }
}

for (const sample of SAMPLES) {
  const btn = h(
    'button',
    { class: 'sample', type: 'button', 'data-sample': sample.id, 'aria-pressed': 'false' },
    h('span', { class: 'sample-name' }, sample.name),
    h('span', { class: 'sample-desc' }, sample.description),
  );
  btn.addEventListener('click', () => {
    textarea.value = sample.logs;
    updateCount();
    selectSample(sample.id);
    showError(null);
    status.textContent = `Loaded demo scenario: ${sample.name}. Press Analyze logs.`;
  });
  sampleList.append(btn);
}

textarea.addEventListener('input', () => {
  updateCount();
  selectSample(null);
});

fileInput.addEventListener('change', () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  if (file.size > MAX_BYTES) {
    showError(
      'That file is larger than 256 KB. Trim it to the relevant time window and try again.',
    );
    fileInput.value = '';
    return;
  }
  void file.text().then((text) => {
    textarea.value = text;
    updateCount();
    selectSample(null);
    showError(null);
    status.textContent = `Loaded ${file.name}.`;
  });
});

const handlers: Handlers = {
  onDecide(action, decision) {
    if (!current) return;
    audit = [...audit, auditEntry(action.id, decision, analyst)];
    renderDecisions(results, current.result, audit);
    status.textContent = `${action.id} ${decision}.`;
  },
  onExportRunbook() {
    if (!current) return;
    download('sanjaya-runbook.md', buildRunbook(current.result, audit), 'text/markdown');
  },
  onExportJson() {
    if (!current) return;
    download(
      'sanjaya-report.json',
      JSON.stringify({ ...current.result, audit }, null, 2),
      'application/json',
    );
  },
  onAnalystChange(name) {
    analyst = name;
  },
};

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const logs = textarea.value;
  if (logs.trim() === '') {
    showError('Paste some log lines or load a demo scenario first.');
    textarea.focus();
    return;
  }
  if (new Blob([logs]).size > MAX_BYTES) {
    showError('Logs must be under 256 KB.');
    return;
  }
  showError(null);
  inflight?.abort();
  inflight = new AbortController();
  button.disabled = true;
  button.textContent = useAi.checked ? 'Sanjaya is looking…' : 'Reading the logs…';
  results.setAttribute('aria-busy', 'true');
  results.replaceChildren(
    h(
      'div',
      { class: 'loading' },
      chakra(),
      h(
        'span',
        {},
        useAi.checked
          ? 'Sanjaya is surveying the battlefield: the rules read every line, then Gemini investigates…'
          : 'The rules are reading every line…',
      ),
    ),
  );
  status.textContent = 'Analysis started.';

  analyze(logs, useAi.checked, inflight.signal)
    .then((result) => {
      current = { result, logs };
      audit = [];
      renderResults(results, result, logs, analyst, handlers);
      renderDecisions(results, result, audit);
      status.textContent = `Analysis complete: ${result.stats.incidents} incident(s), ${result.stats.critical} critical.`;
      byId('report-heading').focus();
    })
    .catch((err: unknown) => {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      results.replaceChildren(hero);
      showError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
      status.textContent = 'Analysis failed.';
    })
    .finally(() => {
      button.disabled = false;
      button.textContent = 'Analyze logs';
      results.removeAttribute('aria-busy');
    });
});

fetchStatus()
  .then((s) => {
    aiStatus.classList.add(s.aiAvailable ? 'online' : 'offline');
    aiStatus.textContent = s.aiAvailable
      ? `Gemini analyst ready (${s.model ?? 'Gemini'})`
      : 'Rule engine only: AI not configured';
    if (!s.aiAvailable) {
      useAi.checked = false;
      useAi.disabled = true;
    }
  })
  .catch(() => {
    aiStatus.classList.add('offline');
    aiStatus.textContent = 'Cannot reach the server';
  });

updateCount();
