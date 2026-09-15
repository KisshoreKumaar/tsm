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

## D-019 — ATT&CK v19.2 renumbering
Every technique ID was checked against attack.mitre.org on 2026-09-15. The spec's T1070.001 (Clear Windows Event
Logs) now redirects to **T1685.005 "Disable or Modify Tools: Clear Windows Event Logs"**, so LOG-001 uses T1685.005.
ATT&CK v19 split the former Defense Evasion tactic into **Stealth** (TA0005) and **Defense Impairment** (TA0112);
T1078 now lists Stealth. Rules take stage names from the verified catalog rather than hardcoding old tactic names.

## D-020 — Phase 1 ingestion and workflow defaults
- `timestamp` is required (no server-time default), so replays and retries stay deterministic.
- `criticality` defaults to 3 (unknown/medium) and `privileged` to false; both are source-reported, not verified.
- Asset, user, domain and hashes are case-folded for correlation; the submitted JSON is stored verbatim (semantic
  JSON, not byte-exact).
- A batch writes one `events.ingested` audit record listing the stored event IDs; duplicates change nothing and are
  not audited.
- PROC-001 also accepts the en/em dash parameter prefixes PowerShell honours, in addition to `-` and `/`.
- FILE-001 counts changes within one correlated component (asset + user); bursts spread across users on one asset
  are not combined.
- Detections are recomputed per component; their IDs are deterministic (UUIDv5 of rule, group and evidence), so
  unchanged detections keep their IDs.
- Adding a note bumps the incident revision and therefore cancels pending/approved responses (spec: any incident
  change cancels them).
- The approval confirmation phrase is `APPROVE SIMULATION`; the UI shows it in the dialog.
- Simulated-response helpers live in `app/response/` (a domain module alongside ingest/detection/correlation).

## D-018 — Provider presets needing verification
The Gemini preset uses the user-supplied `gemini-1.5-flash`; Google may have retired the 1.5 models, so the model field
is editable and Test connection surfaces a rejection. The Ollama server is reachable publicly without authentication;
the team should restrict its security group or tunnel it.

## D-021 — Campaign link rules (F1)
- Links require different assets and activity windows at most `AEGIS_CAMPAIGN_WINDOW_SECONDS` (default 24 h) apart.
- Linkable entities: user, external source IP, external destination IP, domain, file hash. RFC 1918, CGNAT,
  loopback, link-local and ULA addresses never link (shared infrastructure would over-link); documentation ranges
  used by synthetic data count as external.
- The common-entity allowlist accepts `type:value` or `ip:value`. "Maximum link degree" means an entity shared by
  more than `AEGIS_MAX_LINK_DEGREE` incidents creates no links.
- FALSE_POSITIVE and MERGED incidents are excluded, so closing incidents as false positives can dissolve a campaign.
- Campaigns are connected components (transitive): A–B and B–C form one campaign even if A and C are too far apart.
- Campaigns are recomputed inside the transaction that changed incidents (ingestion or review) via incident-change
  hooks; the oldest overlapping campaign keeps its ID, others become MERGED, and unlinked ones become DISSOLVED.
- Link strength is a heuristic: an entity-type weight reduced by up to half as the time gap approaches the window.

## D-022 — Story sentences about AEGIS records (F2)
Event-based FACT sentences must cite at least one event ID. Sentences that state AEGIS's own workflow state (incident
status, response requests, simulated containment) are labelled FACT with `basis: "aegis_records"` and reference the
record IDs instead of events. The citation validator enforces event citations only for `basis: "events"`.
Deterministic stories are rebuilt on every request (always current); "regenerate" saves a version, and the stale flag
compares the latest saved version's incident revision with the current one. AI polish (Phase 3) replaces the
displayed story only when a validated version exists for the current revision.
