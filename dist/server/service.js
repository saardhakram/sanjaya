import { AgentError, runAgent } from './agent/agent.js';
import { rulesTriage } from './agent/rules.js';
import { cacheKey, TtlCache } from './cache.js';
import { materializeActions, runEngine } from './engine/analyze.js';
import { log } from './logger.js';
/**
 * Orchestrates one analysis: deterministic engine first, then (optionally) the
 * Gemini analyst. Every path returns a complete report: if the AI is disabled,
 * unconfigured or fails, the rule-based triage is used and the reason is reported.
 */
export class AnalysisService {
    config;
    client;
    cache;
    constructor(config, client) {
        this.config = config;
        this.client = client;
        this.cache = new TtlCache(config.cache.maxEntries, config.cache.ttlMs);
    }
    get aiAvailable() {
        return this.client !== undefined;
    }
    async analyze(input) {
        const started = Date.now();
        const wantsAi = input.useAi && this.client !== undefined;
        const key = cacheKey(input.logs, wantsAi ? this.config.models.join(',') : 'rules');
        const cached = this.cache.get(key);
        if (cached) {
            return {
                ...cached,
                meta: {
                    ...cached.meta,
                    cached: true,
                    durationMs: Date.now() - started,
                    requestId: input.requestId,
                },
            };
        }
        const state = runEngine(input.logs, { referenceYear: this.config.referenceYear });
        const baseline = state.incidents.map((i) => ({ incidentId: i.id, actions: i.baselineActions }));
        let agent;
        let fallbackReason;
        let tokens = { input: 0, output: 0 };
        if (!this.client)
            fallbackReason = 'Gemini is not configured on this server.';
        else if (!input.useAi)
            fallbackReason = 'AI analyst turned off for this request.';
        else if (state.incidents.length === 0)
            fallbackReason = 'No incidents to investigate.';
        else {
            try {
                agent = await runAgent(this.client, state, {
                    models: this.config.models,
                    ...this.config.agent,
                });
                tokens = agent.tokens;
                if (agent.modelFailures.length > 0) {
                    log('warn', 'model_fallback_used', {
                        requestId: input.requestId,
                        failures: agent.modelFailures,
                    });
                }
            }
            catch (err) {
                fallbackReason = 'The AI analyst was unavailable, so rule-based triage was used.';
                if (err instanceof AgentError)
                    tokens = err.tokens;
                log('warn', 'agent_failed', {
                    requestId: input.requestId,
                    reason: err instanceof Error ? err.message : 'unknown',
                });
            }
        }
        const choices = agent
            ? agent.choices
            : baseline;
        const result = {
            stats: state.stats,
            findings: state.findings,
            incidents: state.incidents,
            actions: materializeActions(choices),
            triage: agent ? agent.triage : rulesTriage(state),
            drishti: state.drishti,
            meta: {
                engine: agent ? 'gemini' : 'rules',
                ...(agent ? { model: agent.model } : {}),
                ...(fallbackReason ? { fallbackReason } : {}),
                tokens,
                agentTurns: agent?.turns ?? 0,
                toolCalls: agent?.toolCalls ?? 0,
                cached: false,
                durationMs: Date.now() - started,
            },
        };
        if (agent || !wantsAi)
            this.cache.set(key, result);
        log('info', 'analysis_complete', {
            requestId: input.requestId,
            engine: result.meta.engine,
            incidents: state.incidents.length,
            tokensIn: tokens.input,
            tokensOut: tokens.output,
            durationMs: result.meta.durationMs,
        });
        return { ...result, meta: { ...result.meta, requestId: input.requestId } };
    }
}
