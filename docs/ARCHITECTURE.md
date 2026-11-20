# Architecture

## Request flow

1. **Validate** (`app.ts`): same-origin check → rate limit → JSON body limit → zod schema (`logs` ≤ 256 KB and ≤ 5,000 lines, `useAi` boolean).
2. **Cache lookup** (`service.ts`): SHA-256 of the logs plus the model chain. A hit returns immediately with `meta.cached = true` and 0 tokens.
3. **Deterministic engine** (`engine/`):
   - `parsers.ts` turns each line into a `LogEvent` (auth / web / firewall / unknown), keeping 1-based line numbers for evidence.
   - `detectors.ts` runs 10 rules with named thresholds and sliding time windows, producing scored, MITRE-mapped `Finding`s.
   - `ml/drishti.ts` (Drishti) builds a behaviour profile per source IP, scores it with three per-group Isolation Forests plus a tail-distance signal, and adds `ml_anomaly` findings only for anomalous IPs (≥ 3 events) that no rule flagged. Every IP's score and reasons go into `result.drishti`.
   - `correlate.ts` uses union-find over `ip:` / `user:` keys, linked by shared findings, successful logins from suspicious IPs, and accounts created through sudo. It builds `Incident`s with chronological kill-chain stages and baseline playbook actions.
4. **Agent** (`agent/`), only when there are incidents and AI is enabled:
   - Starts with a compact overview (no raw logs).
   - Gemini calls `get_incident` / `get_playbook`, which are read-only views of engine state, and must finish with `submit_triage`.
   - The submission is validated by zod and cross-checked: incident IDs exist, every incident is covered, and each action target belongs to its incident. Errors go back to the model for self-correction.
   - Budgets: 6 turns, 20 s per call, 50 s total. If the primary model fails, the fallback model is tried.
5. **Materialise actions** (`engine/playbook.ts`): action IDs plus validated targets become template commands with risk and reversibility metadata.
6. **Fallback** (`agent/rules.ts`): if the agent is disabled or fails, a deterministic triage report is returned with `meta.fallbackReason`.

## Why this split

LLMs are good at explanation and judgement, and bad at counting and following rules exactly when attackers control the input. Sanjaya lets tested code produce every fact and gives the model a narrow, validated interface for the parts that need judgement.

## Front end

- `src/client/` is plain TypeScript bundled by esbuild (~19 KB minified). It has no framework and no runtime dependencies.
- `src/shared/` holds types, the MITRE table, demo scenarios and report/runbook builders, used by both server and client and covered by tests.
- Decisions update the DOM in place, so focus and open evidence panels are preserved.
