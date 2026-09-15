# Feature register

This file is the source of truth for scope. Status values: `planned`, `in-progress`, `done`, `backlog`, `skipped`.
A feature is `done` only after its acceptance tests have been run and passed.

| ID | Feature | Phase | Status | Flag id |
|---|---|---|---|---|
| PLATFORM | Scaffold: config, migrations, feature registry, audit chain, jobs, SSE, FakeProvider, CI, UI shell | 0 | done | `core` (always on) |
| CORE | Ingestion, detection, risk scoring, incidents, simulated response, RBAC, audit, demo scenarios, UI shell | 1 | done | `core` (always on) |
| F1 | Alert correlation: campaigns, entity index, explained links, graph | 2 | done | `f1` |
| F2 | Alert story: deterministic (phase 2), validated AI polish (phase 3) | 2, 3 | done | `f2` |
| X1 | LLM provider settings with a UI API-key field | 3 | done | `x1` |
| F3 | AI analyst (grounded Q&A, quick and deep modes) | 3 | done | `f3` |
| X2 | Agent console: reads every module, proposes changes a human applies | 3 (core), 4–6 (tools) | in-progress (core and F4 tools done; A3/A5/I1 tools arrive with them) | `x2` |
| F4 | Attack prediction, next-step prediction, watchlist | 4 | done | `f4` |
| A3 | AI detection engineer: DSL, backtest, lifecycle | 5 | planned | `a3` |
| A5 | Learning from false positives: analytics, tuning suggestions, suppressions | 5 | planned | `a5` |
| I1 | CERT-In incident report drafts with deadline tracking | 6 | planned | `i1` |
| HARDEN | Evaluation dashboard, security review, cache pre-warming, Docker, docs, demo script, seed data | 7 | planned | — |

Backlog (build only on request): A2 injection showcase, A4 encoded-command decoder, A7 AI scorecard, S1 plain-language
mode, S2 Indian-language summaries, S4 PII masking before AI, I2 DPDP breach draft, I3 compliance control mapping,
I4 Sigma import, I7 SLA tracking, B1 multi-tenant, B2 CloudTrail/Wazuh/Sysmon connectors, B4 ROI dashboard,
G1/G2 rules-first AI gating.

---

## PLATFORM — Phase 0 scaffold

- Numbered, append-only SQL migrations with checksum enforcement; idempotent runner.
- Feature registry with dependencies and `AEGIS_FEATURES`; disabled features return 404 and disappear from the manifest.
- HMAC-SHA256 audit chain written in the same transaction; startup refuses a broken chain or wrong key.
- Persisted job queue with lanes (`default`, `ai`), supersession, cancellation and restart recovery.
- In-process event bus with SSE delivery; payloads carry identifiers only.
- Token identities, permission matrix, security headers, rate limiting, body limits, strict JSON, sanitised errors.
- FakeProvider and DisabledProvider; tests cannot open network connections.
- Makefile, CI workflow, Vite + React + strict TypeScript shell with in-memory token login and lock.

**Acceptance:** backend tests, ruff, mypy, `tsc --noEmit`, vitest and `vite build` pass; a disabled feature's routes
return 404; the migration runner is idempotent and refuses edited migrations; every API route declares exactly one guard.

## CORE — Phase 1

- `POST /api/events` and `POST /api/events/batch` (1–500, atomic), CLI ingester for JSON/JSONL.
- Strict event schema: unknown fields rejected, duplicate keys rejected, typed IPs/ports, length limits, timezone-aware
  timestamps no later than now + clock skew (default 120 s), stored in UTC; raw and normalized copies stored.
- Kinds with required fields: `auth_failure`, `auth_success`, `process_start`, `network_connection`, `file_change`,
  `user_created`, `privilege_change`, `log_cleared`, `suspicious_process`, `malicious_indicator`.
- Idempotent dedup on `(source, event_id)` with canonical-JSON digest.
- Rules AUTH-001, AUTH-002, PROC-001, NET-001, FILE-001, LOG-001, ACCT-001, INJ-001, SOURCE-001/002.
- Incident correlation (same asset + user, chained ±10 min) as connected components (see D-005).
- Explainable capped risk score with named factors and LOW/MEDIUM/HIGH/CRITICAL bands, labelled heuristic.
- Incident workflow with revisions, owner, notes, closing notes, reopening on new evidence, claim labels.
- Simulated response: recommend → approve (confirmation text, revision-bound, 15-min expiry, two-person rule) →
  execute (virtual endpoint registry, read-back verification) or reject; incident changes cancel pending requests.
- Eight synthetic scenarios (instant mode) with unique asset suffixes.
- UI: overview metrics, incident queue (search/filter/pagination), incident page, events explorer, responses, audit.

**Acceptance:** positive/negative/edge unit tests per rule (including every PROC-001 flag spelling); batch
atomicity; dedup semantics; full RBAC matrix; audit verify and tamper refusal; stale revision rejected; approval
expiry and two-person rule (requester cannot approve or execute); execution cannot repeat; ingest role receives IDs only.

## F1 — Alert correlation (Phase 2)

- Entity extraction per event (asset, user, source IP, destination IP, domain, file hash, process), normalised.
- Campaign correlation: incidents sharing a user across assets, an external source IP, or a destination
  IP/domain/hash within 24 h; common-entity allowlist and maximum link degree.
- Link reasons: link type, shared entity, time delta, supporting event IDs, strength.
- Campaign risk, affected assets/users, combined timeline.
- API: `GET /api/campaigns`, `GET /api/campaigns/{id}`, `GET /api/incidents/{id}/related`,
  `GET /api/entities/{type}/{value}`, `GET /api/graph`. UI: correlation graph, campaign page, related panel.

**Acceptance:** attack-chain → exactly 1 incident; benign → 0; Hypothesis permutation test yields identical incident
and campaign partitions; lateral-movement → 3 incidents in 1 campaign with reasons naming the shared user and source
IP; allowlisted entities create no links; merges cancel responses and are audited.

## F2 — Alert story (Phase 2 deterministic, Phase 3 AI polish)

- Stages ordered by earliest evidence timestamp; tactic, candidate technique, time range, event IDs, rule IDs,
  template sentence with concrete values.
- Analyst (150–300 words) and executive (five lines) formats, both cited; Markdown export.
- `story.narrate` AI polish validated against evidence aliases; falls back to deterministic.
- Versioned by incident revision with stale indicator; regenerate; campaign stories combine incident stories.

**Acceptance:** chronological stages including PowerShell-before-logins; every FACT cites ≥1 valid event ID; AI
output citing a non-existent event is rejected (FakeProvider); LLM disabled still renders; injection strings appear
only as quoted data.

## X1 — LLM provider settings with UI API-key field (Phase 3)

- Admin-only Settings → AI Providers (`llm.configure`): presets for Ollama EC2 (native API), Groq, Gemini
  (OpenAI-compatible) and custom; model, base URL, context/output tokens, timeout, redaction, enabled, priority.
- Write-only API-key field; key encrypted with AES-GCM using `AEGIS_SECRET_KEY`; API returns only `key_set` and last
  four characters; audit records set/rotate/remove without the value.
- Test connection (time to first token, tokens/s, JSON mode); set active; fallback chain → deterministic.
- SSRF guard: http/https only, no redirects, link-local/metadata addresses rejected, optional host allowlist.

**Acceptance:** key never appears in any API response (crawl test) or audit record; wrong secret key fails safely;
non-admins get 403; SSRF cases rejected; unreachable provider falls back (MockTransport); no network in tests.

## F3 — AI analyst (Phase 3)

- Chat per incident and campaign with persisted history; each question is an async job streamed over SSE.
- Quick mode (one call over a compact evidence pack) and deep mode (read-only tool loop, step cap, token budget,
  tool result size caps).
- Answer schema: summary, claims (text, label, evidence_ids), suggested questions, suggested actions (text; may
  reference allowlisted playbooks), confidence (heuristic).
- Out-of-scope → UNKNOWN; deterministic template answers when the LLM is disabled; "Add to notes" creates a human note
  referencing the AI job.

**Acceptance:** tool loop terminates; step cap enforced; fake IDs rejected; malformed JSON repaired once or failed
cleanly; injection corpus passes; role without `ai.use` gets 403; every AI call audited.

## X2 — Agent console (Phase 3 core; tools added in Phases 4–6)

- Global drawer with page context; read tools registered by each feature; proposal tools create `agent_proposals`
  (target action, exact payload, bound revision, rationale, evidence) for incident updates, response
  recommendations, rule drafts/backtests, tuning suggestions, CERT-In drafts and demo replays.
- Never proposable: response approve/execute/reject, rule approve/activate/disable, tuning approve/revert, report
  approve/mark-submitted, provider settings, tokens, audit.
- Apply requires the human's own permission for the target action, re-validates revision, and audits both records in
  one transaction; dismiss requires a reason; injection-context proposals need extra acknowledgement.

**Acceptance:** every enabled feature registers ≥1 read tool; human-only actions cannot be proposed; stale proposals
fail to apply; injection corpus cannot yield approve/execute proposals; step cap holds; `ai.use` enforced.

**Phase 3 status:** proposable actions are `incident.update`, `incident.note`, `response.recommend` and
`demo.replay`; read tools cover CORE, F1, F2 and F3. `rule.draft`/`rule.backtest`, `tuning.suggest` and
`report.cert_in.draft` proposals plus their read tools are registered by A3, A5 and I1 in Phases 5–6. F4 registers
`get_predictions` and `list_watchlist` (Phase 4). Manual live check: `scripts/llm_smoke.py`.

## F4 — Attack prediction and watchlist (Phase 4)

- Local ATT&CK catalog (IDs verified against attack.mitre.org, attribution); curated transition model with rationale.
- Context-adjusted relative likelihood score 0–100 with factors (never a probability); predictions labelled
  HYPOTHESIS with watch signals (rule-DSL conditions), preventive actions, horizon.
- Watchlist flips predictions to OBSERVED on matching correlated events (risk rises, live alert, audited); EXPIRED
  after the horizon. `prediction.explain` AI task (may add one catalog-validated "AI candidate"). Hit-rate metric.

**Acceptance:** attack-chain replay: execution prediction appears after brute force + success and flips to OBSERVED
when PowerShell arrives; invalid technique IDs rejected; works with the LLM disabled.

**Phase 4 status:** `data/attack/transitions.json` (12 curated transitions, 9 watch profiles) validated at startup;
engine in `app/prediction/` (pure function of events and detections, arrival-order invariant, see D-026); API
`GET /api/incidents/{id}/predictions`, `POST …/predictions/explain`, `GET /api/predictions`,
`GET /api/metrics/prediction-hit-rate`, `GET /api/attack/transitions`; UI "Likely next" incident tab with prediction
timeline, watchlist page and live "prediction observed" alerts. Evaluation reports observed predictions per scenario.

## A3 — AI detection engineer (Phase 5)

- JSON rule DSL (kinds, field conditions incl. cidr and restricted regex, group_by, window, threshold or
  distinct_count, ordered sequence, severity, techniques, description, known false positives).
- DSL rules share the pipeline and `Detection` objects with built-in rules.
- `rules.draft` AI task; manual editor with live validation; backtest report (matches, would-be incidents, overlap,
  FP-closed hits, benign hits, alerts/day, samples, runtime).
- Lifecycle DRAFT → TESTED → APPROVED → ACTIVE → DISABLED/RETIRED; versions kept; two-person approval; JSON and
  best-effort Sigma export.

**Acceptance:** unknown fields and dangerous regex rejected; rule drafted from lateral-movement backtests with ≥1 hit
on that incident; ACTIVE requires TESTED + approval; active rule fires on ingestion, disabling stops it; invalid AI
DSL repaired once or fails cleanly.

## A5 — Learning from false positives (Phase 5)

- FALSE_POSITIVE closure requires reason category, note and optional benign entities.
- FP analytics per rule/entity/source with trends.
- Suggestions (scoped suppression with mandatory ≤90-day expiry, threshold/window change, DSL exclusion, maintenance
  window) with impact simulation (alerts removed, true positives lost → red + acknowledgement).
- Approval with `tuning.approve`, never auto-applied, one-click revert, protected-rules warning; suppressed detections
  stored as SUPPRESSED and searchable.

**Acceptance:** authorized-scanner closed as FP three times → NET-001 suppression scoped to the scanner IP with alerts
removed and 0 true positives lost; after approval the attack-chain scan from another IP is still detected; expired
suppressions stop applying; revert works; audited.

## I1 — CERT-In incident report drafts (Phase 6)

- Template config `data/compliance/cert_in.json` marked `UNVERIFIED` until checked against official directions.
- Organization profile (admin); deterministic field mapping with provenance (`auto`, `AI`, `human`) and citations;
  `report.cert_in_narrative` AI task from the F2 story.
- Reportability suggestion (labelled "Suggestion — confirm with compliance/legal"); deadline countdown (default 6 h,
  UTC storage, IST display option).
- Workflow DRAFT → IN_REVIEW → APPROVED (`reports.finalize`) → MARKED_SUBMITTED (manual time and reference);
  redaction toggle; Markdown/JSON/print HTML exports; versioned drafts with diff.

**Acceptance:** attack-chain draft has all automatic fields filled and cited; missing organization profile flagged;
deadline correct across time zones; cannot mark submitted without approval; reports module makes no network calls.

## HARDEN — Phase 7

- `scripts/evaluate.py` + metrics dashboard (expected vs actual incidents/campaigns, rules, citation validity,
  prediction hit rate, injection pass rate, backtest figures, CERT-In completeness); non-zero exit on regression.
- Security review, cache pre-warming for the slow model, Docker Compose, README, ARCHITECTURE, API/OpenAPI,
  SECURITY, DEMO (five-minute script), seed data.

**Acceptance:** `make eval` exits 0; the nine-step finale demo works end to end.
