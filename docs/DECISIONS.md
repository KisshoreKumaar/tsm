# Decision log

Small ambiguities are resolved with a sensible default and recorded here. Newest decisions are appended at the end.

## D-001 — Stack as specified
FastAPI + Pydantic v2 + SQLite (WAL, `sqlite3`) + httpx on the backend; React + strict TypeScript + Vite on the
frontend; Cytoscape.js for graphs; Vitest + Testing Library for component tests. No stack changes mid-build.

## D-002 — Python and Node versions
Only Python 3.14 exists on the build machine, so the local venv uses 3.14. `requires-python >=3.11`; CI and Docker
use 3.12. Node 24 locally; CI uses Node 24 (Vite 8 requires ≥20.19 or ≥22.12).

## D-003 — Run through all phases
The user chose to build phases 0–7 back-to-back instead of stopping at each checkpoint. Each phase still ends with
tests, lint, type checks and evaluation green, committed on `phase-N-*` and merged into `main`. One consolidated
report is delivered at the end.

## D-004 — Migration numbering
Phase 0 ships only `0001_platform` (metadata, audit log, jobs). Domain tables arrive in later migrations, so the plan's
table is renumbered by one (`0002_core`, `0003_correlation`, …). Committed migrations are never edited.

## D-005 — Incidents are connected components
Events connect when they share asset + user and are within ±`AEGIS_INCIDENT_WINDOW_SECONDS` (default 600 s) of each
other; chains extend the window. An incident is a component that contains at least one non-suppressed detection.
Components are a pure function of the event set, so the result is independent of arrival order; new events can only
join components (merge) and never split them. Rules evaluate events sorted by `(timestamp, source, event_id,
digest)`, never by random UUID. Tight incident correlation lives in CORE (incidents need it); F1 adds campaigns,
entity pivots, link reasons and the graph.

## D-006 — Story stage order
Stages are ordered by their earliest evidence timestamp (then stage key), never by rule-evaluation order. This fixes the
known prototype bug; a test places PowerShell before the failed logins.

## D-007 — Audit chain details
`audit_log(seq, ts, action, actor, subject_type, subject_id, body, prev_digest, digest)` with
`digest = HMAC-SHA256(key, canonical_json([seq, ts, action, actor, subject_type, subject_id, body, prev]))`.
Update/delete triggers block accidental modification; a keyed fingerprint binds the key to the database; startup
refuses a mismatched key or broken chain. Action names must be registered by a feature. Bodies containing
secret-like keys (`api_key`, `token`, `password`, …) are rejected. Job lifecycle transitions are audited; transient
progress (streamed tokens) is not.

## D-008 — Job lanes and atomic completion
Two lanes: `default` (ingestion follow-ups, replay releases, backtests) and `ai` (LLM calls, concurrency =
`AEGIS_LLM_MAX_CONCURRENCY`). Handlers run outside transactions and return `JobOutcome(result, apply)`; `apply`
runs in the transaction that marks the job SUCCEEDED. A `dedup_key` supersedes queued jobs and requests cancellation
of running ones (used for "latest revision only" precomputation). Restart recovery requeues RUNNING jobs up to three
attempts. Demo replay uses delayed jobs (`run_after`), so it survives restarts.

## D-009 — Live updates
SSE via `StreamingResponse`; the browser reads it with `fetch` so the token stays in the Authorization header.
Payloads contain identifiers and statuses only; clients re-fetch through permission-checked routes.

## D-010 — Permission matrix refinements
- `analyst` also has `tuning.draft` (analysts see false-positive patterns first).
- `audit.export` (checkpoint export) is admin-only; audit read and verify need `read`.
- `settings.manage` (organization profile) and `llm.configure` (providers, keys) are admin-only.
- `/api/me` and `/api/features` accept any authenticated identity, including `ingest`, which receives no nav items.
- Applying an agent proposal requires the permission of the action it targets.
- Two-person mode forbids the requester from approving or executing responses and authors from approving their own
  rules or tuning.

## D-011 — Strict request parsing
A custom route class parses JSON bodies before FastAPI: duplicate keys, NaN/Infinity, nesting deeper than 32 and
non-JSON content types are rejected. Models use `extra="forbid"` and per-field strict types (`StrictInt`,
`StrictBool`) rather than model-wide strict mode, which would reject ISO timestamp strings.

## D-012 — Error hygiene
Validation errors return location, message and type only (no `input`/`ctx`, which could echo secrets or log
content). Unhandled errors return a generic 500 and are logged server-side by exception type.

## D-013 — Rate limiting
Sliding one-minute windows per bearer-token digest (`AEGIS_RATE_LIMIT`, default 600/min) and per client IP (three
times the token limit). `/api/healthz` is exempt.

## D-014 — Frontend lint
Strict `tsc --noEmit` (with `noUnusedLocals`, `noUncheckedIndexedAccess`, etc.) is the frontend lint gate; ESLint is
omitted to keep dependencies minimal.

## D-015 — X1 key storage and egress
Provider API keys entered in the UI are encrypted with AES-GCM using a key derived from `AEGIS_SECRET_KEY` (separate
from the audit key). Without that variable, UI key entry is disabled and env-configured keys still work. Keys are
write-only over the API. Base URLs must be http/https, redirects are not followed, link-local/metadata addresses are
refused and `AEGIS_LLM_ALLOWED_HOSTS` can pin hosts. Redaction defaults on for non-localhost providers.

## D-016 — X2 proposal model
The agent never mutates domain state. Proposal tools write `agent_proposals` rows only (drafts, audited). A human
applies a proposal through the same service function as the manual route, under their own identity and permission,
after revision re-validation. A fixed allowlist defines proposable actions; approval, execution, activation,
finalisation, provider settings, tokens and audit are human-only.

## D-017 — Designing for the measured model
`aegis-fast` generates ~3.85 tokens/s with a 1024-token default context. AEGIS sends per-request overrides (context
2048, output 160, no stop sequence, JSON format), uses evidence aliases (E1…En) mapped server-side to event IDs, short
model-facing keys, chunked tasks when output exceeds the provider's budget, precomputation with supersession, and a
cache keyed by (task, revision, prompt version, provider, model).

## D-018 — Provider presets needing verification
The Gemini preset uses the user-supplied `gemini-1.5-flash`; Google may have retired the 1.5 models, so the model field
is editable and Test connection surfaces a rejection. The Ollama server is reachable publicly without authentication;
the team should restrict its security group or tunnel it.
