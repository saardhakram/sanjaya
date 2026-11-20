import { correlate } from './correlate.js';
import { runDetectors } from './detectors.js';
import { parseLogs } from './parsers.js';
import { buildAction } from './playbook.js';
import { runDrishti } from '../ml/drishti.js';
export function runEngine(text, opts) {
    const parsed = parseLogs(text, opts);
    const ruleFindings = runDetectors(parsed.events);
    // Drishti (ML) adds findings only for anomalous IPs the rules missed.
    const drishti = runDrishti(parsed.events, ruleFindings);
    const findings = [...ruleFindings, ...drishti.findings];
    const incidents = correlate(findings, parsed.events);
    return {
        events: parsed.events,
        findings,
        incidents,
        drishti: drishti.report,
        stats: {
            linesTotal: parsed.linesTotal,
            linesParsed: parsed.linesParsed,
            bySource: parsed.bySource,
            findings: findings.length,
            incidents: incidents.length,
            critical: incidents.filter((i) => i.severity === 'critical').length,
            high: incidents.filter((i) => i.severity === 'high').length,
        },
    };
}
/**
 * Turns chosen actions (from the AI or the rule baseline) into concrete,
 * validated actions with template-generated commands. Invalid choices are dropped.
 */
export function materializeActions(choices) {
    const out = [];
    const seen = new Set();
    for (const { incidentId, actions } of choices) {
        for (const choice of actions) {
            const key = `${incidentId}:${choice.action}:${choice.target ?? ''}`;
            if (seen.has(key))
                continue;
            const built = buildAction(`ACT-${out.length + 1}`, incidentId, choice.action, choice.rationale, choice.target);
            if (!built)
                continue;
            seen.add(key);
            out.push(built);
        }
    }
    return out;
}
