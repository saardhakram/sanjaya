import { describe, expect, it } from 'vitest';
import { AgentError, runAgent } from '../src/server/agent/agent.js';
import { rulesTriage } from '../src/server/agent/rules.js';
import {
  checkSubmission,
  executeTool,
  overview,
  TriageSubmissionSchema,
} from '../src/server/agent/tools.js';
import { callResponse, engine, FakeModel, validSubmission } from './helpers.js';

const opts = {
  models: ['primary', 'fallback'],
  maxTurns: 6,
  callTimeoutMs: 1000,
  totalTimeoutMs: 5000,
};

describe('runAgent', () => {
  it('investigates with tools, then returns a validated report', async () => {
    const state = engine('kill-chain');
    const model = new FakeModel([
      callResponse([
        { name: 'get_incident', args: { incident_id: 'INC-1' }, id: 'c1' },
        { name: 'get_playbook', args: {} },
      ]),
      callResponse([{ name: 'submit_triage', args: validSubmission(state) }]),
    ]);
    const result = await runAgent(model, state, opts);
    expect(result.turns).toBe(2);
    expect(result.toolCalls).toBe(3);
    expect(result.model).toBe('primary');
    expect(result.tokens).toEqual({ input: 2000, output: 400 });
    expect(result.triage.assessments.map((a) => a.incidentId)).toEqual(['INC-1', 'INC-2']);
    // Tool results are fed back as function responses, preserving call ids.
    const toolTurn = model.requests[1]!.contents.at(-1)!;
    expect(toolTurn.parts?.[0]?.functionResponse).toMatchObject({ id: 'c1', name: 'get_incident' });
  });

  it('marks raw log lines as untrusted when returning evidence', () => {
    const state = engine('web-attack');
    const out = executeTool(state, 'get_incident', { incident_id: 'INC-2' });
    expect(out.kind).toBe('data');
    const text = JSON.stringify(out);
    expect(text).toContain('untrusted_log_lines');
    expect(text).toContain('ignore previous instructions');
  });

  it('lets the model self-correct an invalid submission', async () => {
    const state = engine('ssh-compromise');
    const bad = validSubmission(state);
    (bad.incidents as { recommended_actions: unknown[] }[])[0]!.recommended_actions = [
      { action: 'block_ip', target: '8.8.8.8', rationale: 'wrong target' },
    ];
    const model = new FakeModel([
      callResponse([{ name: 'submit_triage', args: bad }]),
      callResponse([{ name: 'submit_triage', args: validSubmission(state) }]),
    ]);
    const result = await runAgent(model, state, opts);
    expect(result.turns).toBe(2);
    const feedback = JSON.stringify(model.requests[1]!.contents.at(-1));
    expect(feedback).toContain('needs a ip target');
  });

  it('reports unknown tools back to the model', async () => {
    const state = engine('ssh-compromise');
    const model = new FakeModel([
      callResponse([{ name: 'run_shell', args: { cmd: 'rm -rf /' } }]),
      callResponse([{ name: 'submit_triage', args: validSubmission(state) }]),
    ]);
    await runAgent(model, state, opts);
    expect(JSON.stringify(model.requests[1]!.contents.at(-1))).toContain('Unknown tool');
  });

  it('nudges the model when it answers with text instead of a tool call', async () => {
    const state = engine('ssh-compromise');
    const model = new FakeModel([
      {
        content: { role: 'model', parts: [{ text: 'hi' }] },
        calls: [],
        usage: { input: 1, output: 1 },
      },
      callResponse([{ name: 'submit_triage', args: validSubmission(state) }]),
    ]);
    const result = await runAgent(model, state, opts);
    expect(result.turns).toBe(2);
  });

  it('falls back to the second model when the first fails', async () => {
    const state = engine('ssh-compromise');
    const model = new FakeModel([
      new Error('503'),
      callResponse([{ name: 'submit_triage', args: validSubmission(state) }]),
    ]);
    const result = await runAgent(model, state, opts);
    expect(result.model).toBe('fallback');
    expect(result.modelFailures).toEqual(['primary: 503']);
    expect(model.requests.map((r) => r.model)).toEqual(['primary', 'fallback']);
  });

  it('gives up when every model fails', async () => {
    const model = new FakeModel([new Error('down')]);
    await expect(runAgent(model, engine('ssh-compromise'), opts)).rejects.toThrow(
      'All models failed',
    );
  });

  it('enforces the turn budget', async () => {
    const model = new FakeModel([callResponse([{ name: 'get_playbook', args: {} }])]);
    const err = await runAgent(model, engine('ssh-compromise'), { ...opts, maxTurns: 3 }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AgentError);
    expect((err as AgentError).tokens.input).toBe(3000);
    expect(model.requests).toHaveLength(3);
  });

  it('enforces the total time budget', async () => {
    const model = new FakeModel([callResponse([{ name: 'get_playbook', args: {} }])]);
    await expect(
      runAgent(model, engine('ssh-compromise'), { ...opts, totalTimeoutMs: -1 }),
    ).rejects.toThrow('Time budget exhausted');
  });

  it('defaults empty action lists to human escalation', async () => {
    const state = engine('ssh-compromise');
    const sub = validSubmission(state);
    (sub.incidents as { recommended_actions: unknown[] }[])[0]!.recommended_actions = [];
    const model = new FakeModel([callResponse([{ name: 'submit_triage', args: sub }])]);
    const result = await runAgent(model, state, opts);
    expect(result.choices[0]!.actions[0]!.action).toBe('escalate_to_human');
  });
});

describe('tool validation', () => {
  const state = engine('kill-chain');

  it('rejects unknown incidents and missing coverage', () => {
    const sub = TriageSubmissionSchema.parse({
      ...validSubmission(state),
      incidents: [{ ...(validSubmission(state).incidents as object[])[0], incident_id: 'INC-99' }],
    });
    const problems = checkSubmission(state, sub);
    expect(problems.join(' ')).toContain('Unknown incident_id "INC-99"');
    expect(problems.join(' ')).toContain('Missing assessments for: INC-1, INC-2');
  });

  it('rejects schema violations such as non-playbook actions', () => {
    const sub = validSubmission(state);
    (sub.incidents as { recommended_actions: unknown[] }[])[0]!.recommended_actions = [
      { action: 'format_disk', rationale: 'nope' },
    ];
    const out = executeTool(state, 'submit_triage', sub);
    expect(out.kind).toBe('error');
  });

  it('returns an error for an unknown incident id', () => {
    const out = executeTool(state, 'get_incident', { incident_id: 42 });
    expect(out).toMatchObject({ kind: 'error' });
  });

  it('builds a compact overview', () => {
    expect(overview(state)).toMatchObject({ stats: { incidents: 2 } });
  });
});

describe('rule-based triage', () => {
  it('summarises incidents deterministically', () => {
    const report = rulesTriage(engine('kill-chain'));
    expect(report.executiveSummary).toMatch(/^2 incident\(s\) found/);
    expect(report.assessments[0]).toMatchObject({
      incidentId: 'INC-1',
      priority: 1,
      confidence: 'high',
      likelyTruePositive: true,
    });
    expect(report.assessments[0]!.attackerObjective).toMatch(/long-term access/);
  });

  it('reports a quiet day', () => {
    expect(rulesTriage(engine('clean')).executiveSummary).toMatch(/No suspicious activity/);
  });
});
