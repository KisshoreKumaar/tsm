# tsm
# AEGIS SOC

An AI-assisted Security Operations workbench. It ingests security telemetry, detects known attack patterns,
correlates alerts into incidents and campaigns, tells the alert story with citations, predicts likely next attacker
steps, answers analyst questions from evidence, helps engineer and tune detections, and drafts CERT-In incident
reports against the reporting deadline.

**Evidence first; AI advises, humans decide.** Every claim cites the events behind it, containment is simulated, the
AI can only draft proposals, and every state change is written to a hash-chained audit log.

## Quick start

```bash
make setup        # virtualenv, pinned backend deps, npm ci
make init-env     # writes .env with random tokens and keys (never commit it)
make seed         # synthetic incidents, tuning verdicts, a rule draft and a CERT-In draft
make dev          # API on 127.0.0.1:8000, UI on 127.0.0.1:5173
make token        # print the local-admin token to sign in with
```

The UI asks for a token; paste the one `make token` prints. `make token NAME=analyst` (or `approver`,
`detection-engineer`, `viewer`, `ingest-bot`) switches roles. Nothing is stored in the browser: the token lives in
memory for the session.

Everything works with no LLM configured. To enable AI features, either set `AEGIS_LLM_*` in `.env` or add a provider
in **Settings → AI Providers** (the API key is write-only, encrypted with `AEGIS_SECRET_KEY`, and never returned).

## What is in the box

| Area | What it does |
|---|---|
| Ingestion and detection | Strict event schema, dedup, ten built-in rules, explainable risk score |
| Incidents | Connected-component correlation, workflow with revisions, simulated response behind approval |
| Campaigns and graph (F1) | Incidents linked by shared entities, with reasons and a correlation graph |
| Alert story (F2) | Chronological, cited narrative in analyst and executive form, plus validated AI polish |
| AI analyst (F3) | Grounded Q&A per incident and campaign, quick and deep (read-only tool) modes |
| Prediction (F4) | Likely next ATT&CK steps with watch signals; predictions flip to OBSERVED live |
| Detection engineering (A3) | JSON rule DSL, backtests, versioned lifecycle with approval, Sigma export |
| Tuning (A5) | Learns from false-positive verdicts; simulated, reversible, human-approved suppressions |
| CERT-In drafts (I1) | Evidence-filled report drafts with provenance, deadline tracking and exports |
| AI providers (X1) | Ollama, Groq, Gemini or any OpenAI-compatible endpoint, with an SSRF guard |
| Agent console (X2) | Reads across every module and drafts proposals a human applies |

Scope and status live in [docs/FEATURES.md](docs/FEATURES.md); the reasoning behind the design is in
[docs/DECISIONS.md](docs/DECISIONS.md).

## Safety posture

- **AI has no write authority.** Agent output is a proposal; applying it needs a human with that action's permission.
- **Simulated response only.** Containment marks a virtual endpoint; nothing is sent to a real device or regulator.
- **Event content is data, never instructions.** Injection attempts are detected, quoted and never followed.
- **Auditable.** Every change is appended to an HMAC-chained log that the app verifies at startup and on demand.
- **Synthetic data.** The demo scenarios use documentation IP ranges and lab hostnames.

More detail: [docs/SECURITY.md](docs/SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/API.md](docs/API.md), [docs/DEMO.md](docs/DEMO.md).

## Verification

```bash
make test    # backend pytest + frontend vitest
make lint    # ruff, mypy, tsc
make eval    # every scenario plus cross-feature workflows; non-zero exit on regression
make verify-audit
```

CI runs the same commands on every push.

## Containers (unverified)

`docker compose up` builds an API image and an nginx image that serves the UI and proxies `/api`. Docker was not
available on the build machine, so these files have never been run: expect small fixes.

```bash
make docker-build && make docker-up   # http://127.0.0.1:8080
```

## Before relying on this outside a lab

- The CERT-In template ships as **UNVERIFIED**; check it against the current official directions.
- Point AEGIS at a private LLM endpoint you control, and keep redaction on.
- Review [docs/SECURITY.md](docs/SECURITY.md) for the deployment assumptions (single-tenant, loopback, no TLS
  terminator included).
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
