# AEGIS SOC — guide for Claude Code sessions

Resume from this file plus `docs/FEATURES.md` (scope and status) and `docs/DECISIONS.md` (why things are the way
they are). The original build specification is `docs/BUILD_PROMPT.md`.

## Project context

- **Product:** AI-assisted Security Operations workbench. Evidence first; AI advises, humans decide.
- **Hackathon:** [HACKATHON NAME]; zonal round [DATE]; finale [DATE]. Team: [N people; owners]. *(placeholders)*
- **Build mode:** phases 0–7 run back-to-back (user choice, 2026-09-15). Every phase still ends with tests, lint,
  type checks and evaluation green, then a commit and a merge of `phase-N-*` into `main`.
- **Additions beyond the spec:** X1 (LLM provider settings with a UI API-key field) and X2 (agent console that
  reaches every module; changes are proposals a human applies).

## Commands

```bash
make setup          # venv + pinned backend deps + frontend npm ci
make init-env       # generate .env with random tokens/keys (never commit it)
make token NAME=local-admin
make dev            # API on 127.0.0.1:8000 + Vite on 127.0.0.1:5173 (proxies /api)
make test           # backend pytest + frontend vitest
make lint           # ruff check + ruff format --check + mypy + tsc --noEmit
make eval           # scenario evaluation; exits non-zero on regression
make demo SCENARIO=attack-chain
make verify-audit / make backup
```

Single backend test: `cd backend && ../.venv/bin/python -m pytest tests/core/test_jobs.py -k dedup -q`.
Single frontend test: `cd frontend && npx vitest run src/core/sse.test.ts`.

## Layout

```text
backend/app/core/        config, db, migrations, auth/permissions, audit chain, jobs, feature registry, SSE, security
backend/app/ingest|detection|correlation|story|prediction|reports|demo/   deterministic domain logic
backend/app/ai/          providers (Fake, Disabled, Ollama, OpenAI-compatible), guardrails, tasks, prompts
backend/app/features/    one package per feature: __init__.py (FEATURE spec), router.py, service.py, models.py, tests/
backend/migrations/      NNNN_name.sql, append-only (checksums enforced at startup)
backend/data/            ATT&CK catalog/transitions, CERT-In template
backend/tests/           cross-cutting tests (RBAC matrix, security, invariants)
frontend/src/core/       api client, auth (token in memory), layout, SSE-over-fetch
frontend/src/features/   one folder per feature; frontend/src/featureManifest.ts wires routes
scripts/                 manage.py (init-env, token, verify-audit, checkpoint, backup), evaluate.py, ingest.py
```

## Conventions

- **Routes:** build routers with `app.core.routing.api_router()` (strict JSON parsing). Every route depends on exactly
  one guard: `require(<permission>)` or `public()`. `tests/core/test_rbac_matrix.py` checks every route × role.
- **Validation:** Pydantic v2 with `extra="forbid"`, `StrictInt`/`StrictBool` where coercion matters, explicit
  length limits. Error responses never echo input values or stack traces.
- **Database:** `with ctx.db.write() as session:` for changes (BEGIN IMMEDIATE, serialised writers). Pass the
  session down; a nested `write()` joins the outer transaction (D-023), so avoid long work inside a write. SQL is
  always parameterised; dynamic fragments come only from fixed allowlists.
- **AI tasks:** run through `ctx.service("ai").run(TaskSpec, build_messages, ...)` from a job on lane `ai`; always
  provide a deterministic fallback. Agent tools are registered via `FeatureSpec.agent_tools` (read tools, or
  `propose_*` tools that only draft `agent_proposals`).
- **Audit:** every state change calls `ctx.audit.append(session, action, actor, body, subject=(type, id))` with the
  same session. Action names are declared in the feature's `FeatureSpec.audit_actions`. Bodies must not contain
  secrets (rejected by key name).
- **Jobs:** `ctx.jobs.enqueue(session, kind, payload, actor, subject=..., dedup_key=...)`. Handlers return
  `JobOutcome(result, apply)`; `apply(session)` commits with the job completion. LLM work uses lane `ai`.
- **Live updates:** `session.after_commit(lambda: ctx.bus.publish("thing.updated", {ids only}))`.
- **Time:** `ctx.clock.now()` (tests use `ManualClock`); store timestamps with `timeutil.iso()` (UTC).
- **AI:** tests use `FakeProvider` only; the network is blocked in `backend/conftest.py`.
- **Frontend:** TypeScript strict; call the API through `useAuth().api`; streams through `core/sse.ts`; the token
  never touches storage, cookies or URLs.
- **New features:** follow `docs/ADDING_A_FEATURE.md` and update `docs/FEATURES.md` / `docs/DECISIONS.md`.

## Non-negotiable invariants

1. AI has no write authority. AI outputs (including X2 agent proposals) are drafts; only a human with the target
   action's permission can apply them. Approve/execute/activate/finalize actions are never proposable.
2. Every FACT cites valid evidence IDs. Unvalidated AI output is never displayed as fact.
3. Event content is data, never instructions. It is never executed, evaluated, or used to fetch anything.
4. The app is fully functional with the LLM disabled. Tests use FakeProvider only.
5. Responses are simulated. Nothing is submitted externally. The only outbound network calls are to LLM endpoints
   an admin configured via environment variables or Settings → AI Providers.
6. Every state change is audited in the same transaction; the audit chain stays verifiable.
7. Detection and correlation results do not depend on event arrival order.
8. Risk and likelihood scores are heuristics and are never labeled probabilities.
9. Only synthetic or authorized lab data. No secrets in the repo. Tokens only in headers. Provider API keys are
   encrypted at rest and never returned by the API.
10. Migrations are append-only. Every feature sits behind a flag.

## Measured LLM facts (2026-09-15)

- Ollama at `http://13.235.64.41:11434`, model `aegis-fast` (phi4-mini 3.8B Q4_K_M). Modelfile: `num_ctx 1024`,
  `num_predict 55`, `stop "\n\n"`, `temperature 0`. Per-request overrides work (native `options`; `/v1` `max_tokens`).
- ~3.85 generated tokens/s, ~32 prompt tokens/s → 45–70 s per grounded call. Design for evidence aliases (E1…),
  compact JSON, chunked tasks, precomputation and deterministic fallbacks.
- The server is publicly reachable without authentication; redaction defaults on for it.
