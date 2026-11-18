import type { Content, Part } from '@google/genai';
import type { ProposedActionInput, TriageReport } from '../../shared/types.js';
import type { EngineResult } from '../engine/analyze.js';
import type { ModelClient, ModelResponse } from './model.js';
import { SYSTEM_INSTRUCTION, initialUserMessage } from './prompt.js';
import { TOOL_DECLARATIONS, executeTool, overview, type TriageSubmission } from './tools.js';

/**
 * Bounded function-calling loop: the model investigates with read-only tools
 * and must finish through `submit_triage`, whose output is validated against
 * the engine state. Turn, per-call and total time budgets keep cost and
 * latency predictable; a fallback model is tried if the primary one fails.
 */

export interface AgentOptions {
  models: readonly string[];
  maxTurns: number;
  callTimeoutMs: number;
  totalTimeoutMs: number;
}

export interface AgentResult {
  triage: TriageReport;
  choices: { incidentId: string; actions: ProposedActionInput[] }[];
  model: string;
  turns: number;
  toolCalls: number;
  tokens: { input: number; output: number };
  /** Short, key-free reasons for models that failed before one succeeded. */
  modelFailures: string[];
}

export class AgentError extends Error {
  constructor(
    message: string,
    readonly tokens: { input: number; output: number },
  ) {
    super(message);
    this.name = 'AgentError';
  }
}

function toReport(sub: TriageSubmission): Pick<AgentResult, 'triage' | 'choices'> {
  const sorted = [...sub.incidents].sort((a, b) => a.priority - b.priority);
  return {
    triage: {
      executiveSummary: sub.executive_summary,
      analystNotes: sub.analyst_notes,
      assessments: sorted.map((i) => ({
        incidentId: i.incident_id,
        priority: i.priority,
        assessment: i.assessment,
        attackerObjective: i.attacker_objective,
        confidence: i.confidence,
        likelyTruePositive: i.likely_true_positive,
      })),
    },
    choices: sorted.map((i) => ({
      incidentId: i.incident_id,
      actions:
        i.recommended_actions.length > 0
          ? i.recommended_actions.map((a) => ({
              action: a.action,
              rationale: a.rationale,
              ...(a.target ? { target: a.target } : {}),
            }))
          : [
              {
                action: 'escalate_to_human',
                rationale: 'No automated action recommended; human review.',
              },
            ],
    })),
  };
}

export async function runAgent(
  client: ModelClient,
  state: EngineResult,
  opts: AgentOptions,
): Promise<AgentResult> {
  const started = Date.now();
  const tokens = { input: 0, output: 0 };
  const contents: Content[] = [
    { role: 'user', parts: [{ text: initialUserMessage(JSON.stringify(overview(state))) }] },
  ];
  let modelIndex = 0;
  let toolCalls = 0;
  const failures: string[] = [];

  const call = async (): Promise<ModelResponse> => {
    for (;;) {
      const model = opts.models[modelIndex];
      if (!model) throw new AgentError(`All models failed: ${failures.join(' | ')}`, tokens);
      const remaining = opts.totalTimeoutMs - (Date.now() - started);
      if (remaining <= 0) throw new AgentError('Time budget exhausted', tokens);
      const signal = AbortSignal.timeout(Math.min(opts.callTimeoutMs, remaining));
      try {
        return await client.generate({
          model,
          systemInstruction: SYSTEM_INSTRUCTION,
          contents,
          tools: TOOL_DECLARATIONS,
          signal,
        });
      } catch (err) {
        // Keep a short, key-free reason for the server log.
        const reason = err instanceof Error ? err.message : String(err);
        failures.push(`${model}: ${reason.replace(/key=[^&\s]+/gi, 'key=***').slice(0, 200)}`);
        modelIndex++;
      }
    }
  };

  for (let turn = 1; turn <= opts.maxTurns; turn++) {
    const response = await call();
    tokens.input += response.usage.input;
    tokens.output += response.usage.output;
    contents.push(response.content);

    if (response.calls.length === 0) {
      contents.push({
        role: 'user',
        parts: [{ text: 'Respond only with tool calls. Call submit_triage when you are done.' }],
      });
      continue;
    }

    toolCalls += response.calls.length;
    const outcomes = response.calls.map((c) => ({
      call: c,
      outcome: executeTool(state, c.name, c.args),
    }));
    const submitted = outcomes.find((o) => o.outcome.kind === 'submitted');
    if (submitted?.outcome.kind === 'submitted') {
      return {
        ...toReport(submitted.outcome.submission),
        model: opts.models[modelIndex] ?? 'unknown',
        turns: turn,
        toolCalls,
        tokens,
        modelFailures: failures,
      };
    }

    const parts: Part[] = outcomes.map(({ call: c, outcome }) => ({
      functionResponse: {
        ...(c.id ? { id: c.id } : {}),
        name: c.name,
        response: outcome.kind === 'submitted' ? {} : outcome.response,
      },
    }));
    contents.push({ role: 'user', parts });
  }

  throw new AgentError(`No valid submission within ${opts.maxTurns} turns`, tokens);
}
