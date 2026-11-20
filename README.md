# Sanjaya: divya drishti for your security logs

> In the Mahabharata, Sanjaya was given _divya drishti_ (divine sight). He saw the entire Kurukshetra battlefield and narrated it, faithfully and without taking sides, to the blind king Dhritarashtra. This app does the same for your logs: it sees every line, reconstructs the attack, and explains it truthfully to the person who has to decide what to do.

> **PromptWars × AgentX 2.0 · PS06: AI-Powered Cybersecurity Triage**
> A defensive agent that analyses security logs, correlates alerts, detects suspicious activity and recommends safe remediation, with a human approving every step.

**Live demo:** https://sanjaya.embarko.app (hosted on Embarko) · mirror: https://sanjaya-dun.vercel.app · Click a demo scenario, then **Analyze logs**. Try **Low and slow** to watch the ML model catch what the rules miss.

---

## The problem

Small teams get thousands of log lines and no SOC. Existing tools either drown them in raw alerts or hand the decision to a black-box AI that can hallucinate, be manipulated by attacker-controlled log text, or run destructive commands. Analysts need **fast, explainable triage they can trust and verify**.

## What Sanjaya does

| Step                 | What happens                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Who decides           |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| **1. Detect**        | Parses Linux auth, Apache/Nginx and UFW/iptables logs. Ten tested detectors flag brute force, password spraying, successful compromise, root shells, backdoor accounts, port scans, SQLi / traversal / command injection / XSS, scanners, enumeration and **prompt-injection text planted for AI tools**.                                                                                                                                                               | Deterministic code    |
| **1b. Drishti (ML)** | An **unsupervised anomaly model** (Isolation Forest, written from scratch in TypeScript) learned from 4,000 normal clients of nine kinds. It scores every IP from 16 behaviour features (login failures, request rate, error mix, code-like URL characters, ports touched) and **flags attacks no rule describes**: slow password guessing, data scraping, novel injection payloads. Each flag comes with plain-English reasons, e.g. _failed logins 14, normally ≤ 2_. | ML model (calibrated) |
| **2. Correlate**     | Union-find links IPs ↔ accounts ↔ sudo activity, so _scan → brute force → login → root → backdoor_ becomes **one multi-stage incident** with kill-chain stages in the order they happened, mapped to MITRE ATT&CK.                                                                                                                                                                                                                                                      | Deterministic code    |
| **3. Investigate**   | A **Gemini function-calling agent** pulls evidence through tools, explains each incident in plain English, infers the attacker's objective, prioritises incidents, and picks responses **only from a fixed playbook**.                                                                                                                                                                                                                                                  | Gemini (validated)    |
| **4. Approve**       | Every action shows its risk, reversibility and a template-generated command. The analyst approves or rejects each one (high-risk ones need a second confirmation). Approved steps export as a Markdown runbook with an audit trail.                                                                                                                                                                                                                                     | **Human**             |

### Design principles

- **Numbers come from code, never from the LLM.** Scores, severities, counts, IPs and timestamps are computed by tested detectors. The model adds narrative, priority and a choice of actions.
- **The AI cannot write commands.** It picks an action ID from the playbook; commands come from templates, and targets are inserted only after strict IP/username validation. A malicious username like `x;rm -rf /` in a log can never reach a suggested command.
- **Logs are untrusted.** Evidence is passed to Gemini under an `untrusted_log_lines` key, the system instruction forbids following instructions inside it, and a detector flags injection attempts (MITRE ATLAS `AML.T0051`).
- **ML raises leads, people decide.** Drishti only adds findings for IPs the rules missed, needs at least 3 events, is capped below "critical", and Gemini is told to treat its flags as leads to verify.
- **Human in the loop.** Sanjaya never executes anything.
- **Always answers.** With no API key, a model outage, or a time/turn budget hit, the rule-based triage still returns a complete report and says why.

## Architecture

```
Browser (vanilla TS, strict CSP, WCAG-minded)
   │  POST /api/analyze {logs, useAi}
   ▼
Express on Cloud Run ── zod validation · same-origin check · rate limit · 256 KB cap
   │
   ├─ engine/parsers.ts     auth / web / firewall → LogEvent[]
   ├─ engine/detectors.ts   10 rules → Finding[] (scored 0–100, MITRE-mapped)
   ├─ ml/drishti.ts         per-IP features → 3 Isolation Forests + tail distance
   │                        → anomaly score 0–100 + reasons; ml_anomaly findings
   ├─ engine/correlate.ts   union-find → Incident[] + baseline playbook actions
   │
   ├─ agent/agent.ts        bounded Gemini loop (≤6 turns, 20 s/call, 50 s total,
   │     │                  model fallback, response cache)
   │     ├─ tools: get_incident · get_playbook · submit_triage (zod + cross-checks)
   │     └─ model.ts        @google/genai, function calling mode ANY, safety settings
   │
   └─ engine/playbook.ts    action templates + target validation → ProposedAction[]
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow and [SECURITY.md](SECURITY.md) for the threat model.

## Drishti: the machine-learning third eye

Rules only catch what someone thought to write down. Drishti learns what _normal_ looks like and flags whatever is far from it.

- **Features** (`ml/features.ts`): for each source IP, 16 behaviour features in three groups. Logins: attempts, failures, failure share, non-existent users, usernames tried. Web: requests, peak per minute, 4xx and 5xx share, distinct URLs, code-like characters, URL length, non-browser share. Firewall: events, block share, distinct ports. Counts are log-scaled and shares are smoothed (`k / (n + 4)`) so one 404 out of one request is not "100% errors".
- **Model** (`ml/iforest.ts`, `ml/model.ts`): one Isolation Forest per group (100 trees, ψ = 256), because forests blur in high dimensions and an IP that never logged in should not be judged on logins. Isolation Forest cannot score a point beyond the most extreme training point, so it is paired with a **tail-distance** signal (how far the most extreme feature sits beyond the benign 99th percentile). Each group's threshold is calibrated so only 0.1% of benign training clients reach it.
- **Training** (`ml/baseline.ts`, `npm run train:ml`): 4,000 synthetic benign clients (shoppers, mobile apps, crawlers, uptime monitors, developers with curl, SSH admins with typos, internet background noise) written in real log formats and passed through the same parser as user input. Training is seeded and reproducible; a test retrains and checks the committed model matches exactly. For a real deployment, pass your own known-good logs: `npm run train:ml -- normal.log`.
- **Measured**: 0.13% false-positive rate on 12,000 held-out benign clients; all attackers in the demo scenarios flagged; the _Low and slow_ scenario contains three attacks that **no rule catches and Drishti catches all three**.
- **Explainable**: every flag lists the features that stood out and what normal looks like.

## Google services used

- **Gemini API** (`@google/genai`): a function-calling agent with system instructions, forced tool use (`mode: ANY`), three tools, safety settings, token accounting and a primary → fallback model chain (`gemini-3.1-flash-lite` for speed, falling back to `gemini-3.5-flash`; configurable). In production this fallback already kept the analyst online when the primary model returned 503 "high demand". Full model turns are kept in history, so Gemini 3 thought signatures are preserved.
- **Google Cloud Run ready**: containerised, non-root, `$PORT`, `/healthz`, graceful SIGTERM shutdown (the live demo runs on Vercel's Express runtime from the same code).
- **Google Cloud Logging**: structured JSON logs (`severity`, request IDs, token usage, latency) that Cloud Run ingests automatically. User log text is never logged.

## Quality

| Area              | How                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Testing**       | 116 Vitest tests, ~99% line coverage (server, agent and browser UI) with CI-enforced thresholds. Parsers, every detector (positive and negative cases), correlation, playbook injection safety, the agent loop with a scripted fake Gemini (self-correction, unknown tools, turn and time budgets, model fallback), the ML model (forest maths, determinism, reproducible training, held-out false-positive rate, catching rule-evading attacks, staying quiet on normal traffic), HTTP hardening, caching, rate limiting, report export, and the browser UI in jsdom (rendering, approvals, uploads, errors, and a test proving attacker log text is never rendered as markup). Plus an end-to-end smoke test against the built container. |
| **Security**      | API key server-side only · strict CSP with no `unsafe-inline` (own header middleware, no extra dependency) · HSTS, nosniff, frame-ancestors none, COOP, Permissions-Policy · same-origin API · per-IP rate limit · body and line caps · zod validation · generic errors with request IDs · non-root container · Dependabot · `npm audit` clean.                                                                                                                                                                                                                                                                                                                                                                                             |
| **Efficiency**    | Deterministic pre-analysis means the model only sees compact incident summaries, not raw logs (about 3–6k tokens per run). Identical requests are served from a TTL/LRU cache with zero tokens. The agent is bounded by turns and time, tool calls are batched per turn, and the client bundle is ~19 KB with no framework.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Accessibility** | Semantic landmarks, skip link, labelled controls, `aria-live` status, `role="alert"` errors, focus moved to results, `aria-pressed` toggles, keyboard-only operable, visible focus, severity shown as text as well as colour, light/dark themes, `prefers-reduced-motion`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **Code quality**  | TypeScript strict + `noUncheckedIndexedAccess`, type-aware ESLint, Prettier, small single-purpose modules, shared types between server and client.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

## Run locally

```bash
npm ci
cp .env.example .env            # add GEMINI_API_KEY (optional; rules-only without it)
npm run build
GEMINI_API_KEY=... npm start    # http://localhost:8080
npm run check                   # typecheck + lint + tests with coverage
```

## Deploy to Cloud Run

One command in [Google Cloud Shell](https://shell.cloud.google.com) (creates/links the project, enables APIs, asks for the Gemini key without echoing it, deploys with max 2 instances, then smoke-tests):

```bash
git clone https://github.com/saardhakram/sanjaya && bash sanjaya/scripts/deploy-cloudrun.sh
```

Or manually:

```bash
gcloud run deploy sanjaya \
  --source . --region asia-south1 --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=YOUR_KEY \
  --memory 512Mi --max-instances 3
node scripts/smoke.mjs https://<service-url>
```

(For production, store the key in Secret Manager and use `--set-secrets GEMINI_API_KEY=gemini-key:latest`.)

## Assumptions and limits

- Syslog timestamps have no year, so the current year is assumed (`REFERENCE_YEAR` overrides it).
- Detection thresholds are conservative defaults (5 failures/10 min, 10 ports/5 min, 15 × 404/5 min). They are named constants in `detectors.ts`.
- Approvals live in the browser session and export as a runbook. There is no server-side state, by design.
- Demo data uses RFC 5737 documentation IPs only.
- Drishti is trained on synthetic benign traffic. It is a good general baseline, but any real site should retrain it on its own normal logs (one command, above).

## License

MIT
