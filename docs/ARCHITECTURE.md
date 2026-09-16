# Architecture

## Shape

```text
sources / CLI / demo replay
        │
        ▼
POST /api/events ──► validate (strict Pydantic) ──► store raw + normalised + entities
        │
        ▼
correlation: rebuild the affected component (asset + user, chained ±10 min)
        │
        ├─► detection engine: built-in rules + ACTIVE DSL rules (A3) + tuning overrides (A5)
        ├─► suppression checks (A5) ──► detections ACTIVE or SUPPRESSED
        ├─► risk score (explainable factors)
        └─► incident upsert ──► incident-change hooks, all in one transaction:
                   campaigns (F1) · story polish (F2) · predictions (F4) · tuning generation (A5)
        │
        ▼
audit log (HMAC chain) ─── SSE /api/stream (ids only) ───► React UI
        │
        ▼
job queue (lanes: default, ai) ──► AI tasks ──► provider chain ──► validated output or deterministic fallback
```

## Layers

| Layer | Contents | Rule |
|---|---|---|
| `app/core/` | config, db, migrations, auth, audit, jobs, SSE, features, security, routing | No feature logic |
| `app/ingest|detection|correlation|story|prediction|rules|tuning|reports|response|demo/` | deterministic domain logic | Pure functions of their inputs; no HTTP, no AI |
| `app/ai/` | providers, evidence packs, guardrails, prompts, tasks, tool registry | Never writes domain state |
| `app/features/<id>/` | `__init__.py` (FeatureSpec), `router.py`, `service.py`, `tests/` | Orchestration only |
| `frontend/src/core/` | API client, auth, layout, SSE-over-fetch, shared UI | No feature imports |
| `frontend/src/features/<id>/` | pages and components for one feature | Registered in `featureManifest.ts` |

## Extension points

- **FeatureSpec** — `depends_on`, `router`, `jobs`, `audit_actions`, `agent_tools`, `nav`, `on_startup`. A disabled
  feature is not mounted: its routes 404 and it disappears from the manifest and the UI.
- **Incident-change hooks** — `pipeline.change_hooks`; run inside the transaction that changed the incidents.
- **Suppression checks** — `pipeline.suppression_checks`; return a suppression ID to mark a detection SUPPRESSED.
- **Rule providers and parameter overrides** — `engine.add_provider`, `engine.set_parameter_provider`.
- **Agent tools** — read tools and `propose_*` tools registered per feature; proposals are drafts only.
- **AI tasks** — `TaskSpec(name, prompt_version, parse, fallback)` run through `AIRuntime.run`.

## Data and transactions

- SQLite in WAL mode, one connection per unit of work, `BEGIN IMMEDIATE` for writes. A nested `write()` joins the
  outer transaction (D-023), so a domain call, its audit record and its job enqueue commit together or not at all.
- Migrations are numbered, append-only and checksummed; the runner refuses an edited migration.
- Ordering never depends on arrival: components are rebuilt from stored events, and ties break on `rowid`, not on
  random UUIDs.

## AI path

1. A job on the `ai` lane builds an evidence pack: aliases `E1…En`, a token budget, optional reversible redaction.
2. The provider chain is tried in order (test override → active provider → others by priority → environment).
3. Output is parsed and validated: claims must cite real aliases, instruction-like text is dropped, unsafe suggested
   actions are filtered out.
4. On failure there is one repair retry, then the deterministic fallback. Every call is recorded in `ai_calls` and
   audited as `ai.call`.

## Live updates

State changes publish ids-only events after commit; the browser reads `/api/stream` with `fetch` (not `EventSource`)
so the token stays in the `Authorization` header. Job progress, including streamed tokens, goes to
`/api/jobs/{id}/stream`.
