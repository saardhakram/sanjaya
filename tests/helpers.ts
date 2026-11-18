import type { ModelClient, ModelRequest, ModelResponse } from '../src/server/agent/model.js';
import { loadConfig, type Config } from '../src/server/config.js';
import { runEngine, type EngineResult } from '../src/server/engine/analyze.js';
import { SAMPLES } from '../src/shared/samples.js';

export function sample(id: string): string {
  const s = SAMPLES.find((x) => x.id === id);
  if (!s) throw new Error(`no sample ${id}`);
  return s.logs;
}

export function engine(id: string): EngineResult {
  return runEngine(sample(id), { referenceYear: 2026 });
}

export function testConfig(overrides: Partial<Config> = {}): Config {
  return { ...loadConfig({ REFERENCE_YEAR: '2026' }), ...overrides };
}

type Step = ModelResponse | Error | ((req: ModelRequest) => ModelResponse | Promise<ModelResponse>);

/** Scripted fake Gemini: returns the next step for each call and records requests. */
export class FakeModel implements ModelClient {
  readonly requests: ModelRequest[] = [];
  private i = 0;

  constructor(private readonly steps: Step[]) {}

  async generate(req: ModelRequest): Promise<ModelResponse> {
    this.requests.push({ ...req, contents: [...req.contents] });
    const step = this.steps[Math.min(this.i++, this.steps.length - 1)];
    if (step === undefined) throw new Error('no steps');
    if (step instanceof Error) throw step;
    if (typeof step === 'function') return step(req);
    return step;
  }
}

export function callResponse(
  calls: { name: string; args: Record<string, unknown>; id?: string }[],
): ModelResponse {
  return {
    content: {
      role: 'model',
      parts: calls.map((c) => ({ functionCall: { name: c.name, args: c.args } })),
    },
    calls,
    usage: { input: 1000, output: 200 },
  };
}

/** A valid submission covering every incident of the given engine state. */
export function validSubmission(state: EngineResult): Record<string, unknown> {
  return {
    executive_summary: 'An attacker brute-forced SSH, gained root and created a backdoor account.',
    analyst_notes: 'One log line attempted to instruct AI tools; ignored.',
    incidents: state.incidents.map((inc, i) => ({
      incident_id: inc.id,
      priority: i + 1,
      assessment: `Assessment for ${inc.id}.`,
      attacker_objective: 'Gain persistent root access.',
      confidence: 'high',
      likely_true_positive: true,
      recommended_actions: [
        ...(inc.ips[0]
          ? [{ action: 'block_ip', target: inc.ips[0], rationale: 'Stop the attacker.' }]
          : []),
        { action: 'escalate_to_human', rationale: 'Confirm scope.' },
      ],
    })),
  };
}
