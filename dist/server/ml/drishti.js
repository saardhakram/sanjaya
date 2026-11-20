import { severityFor, THRESHOLDS } from '../engine/detectors.js';
import { profilesFrom } from './features.js';
import { DRISHTI_MODEL, judge } from './model.js';
/**
 * Drishti ("sight"), the third eye: runs the anomaly model over every source
 * IP and turns the anomalous IPs that no rule caught into findings, so they
 * flow through correlation, the AI analyst and human approval like any other.
 *
 * Guard rails:
 *  - At least MIN_EVENTS events are needed before behaviour is judged.
 *  - ML-only findings are capped below "critical": an unsupervised model
 *    raises leads for a human, it does not convict.
 */
export const DRISHTI = {
    minEvents: 3,
    maxFindingScore: 84,
};
const GROUP_WORD = {
    auth: 'login',
    web: 'web',
    network: 'network',
};
/** Which ATT&CK technique the behaviour most likely corresponds to. */
function likelyTechniques(verdict, loggedIn) {
    const features = new Set(verdict.reasons.map((r) => r.feature));
    const out = [];
    switch (verdict.top.group) {
        case 'auth':
            out.push('T1110.001');
            if (loggedIn)
                out.push('T1078');
            break;
        case 'network':
            out.push('T1046');
            break;
        case 'web':
            // Long URLs alone are not an exploit signal (scrapers page through long query strings).
            if (['oddCharRatio', 'http5xxRatio'].some((f) => features.has(f))) {
                out.push('T1190');
            }
            else if (['http4xxRatio', 'distinctPaths'].some((f) => features.has(f))) {
                out.push('T1595.003');
            }
            else {
                out.push('T1119');
            }
            break;
    }
    return out;
}
/** A successful login that came after failed attempts from the same IP. */
function loginAfterFailures(events) {
    let failures = 0;
    for (const e of events) {
        if (e.kind === 'auth_failure' || e.kind === 'invalid_user')
            failures++;
        else if (e.kind === 'auth_success' && failures >= 3)
            return e;
    }
    return undefined;
}
function toFinding(id, profile, verdict) {
    const login = verdict.top.group === 'auth' ? loginAfterFailures(profile.events) : undefined;
    const user = login?.user;
    const evidenceEvents = profile.events.filter((e) => verdict.top.group === 'auth'
        ? e.kind === 'auth_failure' || e.kind === 'invalid_user' || e.kind === 'auth_success'
        : verdict.top.group === 'web'
            ? e.kind === 'http_request'
            : e.kind === 'firewall_block' || e.kind === 'firewall_allow');
    const times = evidenceEvents.map((e) => e.timestamp).filter((t) => t !== null);
    const score = Math.min(DRISHTI.maxFindingScore, Math.round(40 + (verdict.score - 50) * 0.8) + (user ? 10 : 0));
    const why = verdict.reasons.map((r) => `${r.label.toLowerCase()} ${r.value} (normal ${r.typical})`);
    const finding = {
        id,
        detector: 'ml_anomaly',
        title: user
            ? `Unusual login pattern from ${profile.ip}, then logged in as ${user}`
            : `Unusual ${GROUP_WORD[verdict.top.group]} behaviour from ${profile.ip}`,
        severity: severityFor(score),
        score,
        techniques: likelyTechniques(verdict, Boolean(user)),
        ip: profile.ip,
        firstSeen: times.length ? Math.min(...times) : null,
        lastSeen: times.length ? Math.max(...times) : null,
        count: evidenceEvents.length,
        evidence: evidenceEvents.slice(0, THRESHOLDS.maxEvidence).map((e) => e.line),
        details: `Drishti anomaly model scored this IP ${verdict.score}/100 (flagged from 50); no rule matched it. ` +
            `Stood out: ${why.join('; ')}.` +
            (user ? ` It then logged in successfully as "${user}".` : ''),
    };
    if (user)
        finding.user = user;
    return finding;
}
/**
 * Scores every IP and creates findings for anomalous IPs that rules missed.
 * New finding ids continue after the rule findings (F-00n).
 */
export function runDrishti(events, ruleFindings, model = DRISHTI_MODEL) {
    const ruleIps = new Set(ruleFindings.map((f) => f.ip).filter(Boolean));
    const judged = profilesFrom(events)
        .map((profile) => ({
        profile,
        verdict: judge(profile.vector, profile.raw, profile.groups, model),
    }))
        .filter((x) => x.verdict !== null)
        .sort((a, b) => b.verdict.score - a.verdict.score);
    const findings = [];
    const entities = judged.map(({ profile, verdict }) => {
        const ruleFlagged = ruleIps.has(profile.ip);
        const enough = profile.events.length >= DRISHTI.minEvents;
        const anomalous = verdict.anomalous && enough;
        if (anomalous && !ruleFlagged) {
            const id = `F-${String(ruleFindings.length + findings.length + 1).padStart(3, '0')}`;
            findings.push(toFinding(id, profile, verdict));
        }
        return {
            ip: profile.ip,
            score: verdict.score,
            anomalous,
            ruleFlagged,
            events: profile.events.length,
            groups: profile.groups,
            reasons: verdict.reasons,
        };
    });
    return {
        report: {
            model: model.version,
            trainingProfiles: model.trainingProfiles,
            trees: model.groups.reduce((n, g) => n + g.forest.trees.length, 0),
            entities,
            flagged: entities.filter((e) => e.anomalous).length,
            newFindings: findings.length,
        },
        findings,
    };
}
