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

## D-023 — Nested database writes join the outer transaction
`Database.write()` is reentrant per thread: a nested `write()` yields the same session, and `read()` inside a write
reuses the write connection so it sees uncommitted changes. Only the outermost block commits or rolls back, and
after-commit callbacks run once, after that commit. This lets X2 apply a proposal by calling the ordinary domain
service (which opens its own write) while the proposal status and both audit records land in one transaction.

## D-024 — AI runtime for a slow, small model
- Provider order: test override → active Settings provider → other enabled providers by priority → environment
  provider → deterministic fallback. Admins can force deterministic mode (`ai_deterministic_only`).
- Each task has a Pydantic-free parser that raises `OutputInvalid`; one repair retry, then the task's deterministic
  fallback with `ai_status` recording why. Every call (including cache hits and failures) is a row in `ai_calls` and
  an `ai.call` audit record with provider, model, prompt version and hash, token counts, latency and outcome.
- Cache key: task, subject revision, prompt version, provider, model and prompt hash.
- Evidence reaches the model as aliases E1…En inside `<data>` with compact arrays, token-budgeted per provider; the
  redactor replaces users, emails and IPs with USER_n/EMAIL_n/IP_n and restores them in validated output only.
- Claim validation: unknown aliases are dropped, a FACT without a surviving citation becomes INFERENCE, claims echoing
  instruction-like evidence text are removed, and suggested actions that approve, execute, disable or delete are dropped.
- Story polish (F2) runs as a debounced `story.polish` job on the `ai` lane; on small-context providers stories are
  polished two sentences per call. A rewrite must keep sentence ids, labels, citations and every number; otherwise
  the deterministic story stays.
- Deep mode and the agent use a provider-agnostic JSON tool protocol (`{"tool","args"}` / `{"final"}`) with a step cap
  of 3 on providers with ≤4096 context tokens and 6 otherwise; tool results are truncated to 1200 characters.

## D-025 — Agent proposals (X2)
- The agent is a tool loop with read tools plus `propose_*` tools; a run stores at most three proposals, each bound to
  the target's revision, with rationale, cited event IDs and an `injection_context` flag.
- The proposable-action allowlist and the human-only list are disjoint by assertion and by test. Applying checks the
  applying human's permission for the target action (not `ai.use`), re-checks the revision (stale → `STALE`, 409), and
  requires `acknowledge_injection` for injection-context proposals.
- The agent's actor string is `ai:agent (for <human>)`; the applied domain change is attributed to the human who
  applied it, and the `agent.proposal_applied` audit record links both.

## D-026 — Prediction semantics (F4)
- Predictions are a pure function of an incident's stored events and active detections, evaluated in event time, so
  arrival order never changes them. The watchlist is that recomputation run in the incident-change hook (same
  transaction), plus a delayed `prediction.expire` job.
- A candidate is not predicted when its technique was already established before its predecessor's first evidence.
- **OBSERVED:** an event outside the predecessor detection's own evidence, timestamped between that detection's first
  evidence and its last evidence plus the horizon, matches a watch signal. Rule-based signals match the event that
  completed the detection (its latest evidence), not every evidence event.
- **EXPIRED:** still unobserved when the clock passes the end of the window. A late-arriving event whose timestamp
  falls inside the window still marks it OBSERVED (event time wins).
- One prediction per incident and technique. Several predecessors corroborate (+5) and each opens its own window;
  the strongest transition supplies the base weight and rationale.
- Score: transition weight (≤60) + privileged account (10) + successful authentication (10) + asset criticality (≤8) +
  stages observed (≤9) + recency relative to the incident's latest event (≤8) + campaign breadth (≤5) +
  corroboration (5), capped at 100; bands LOW < 35 ≤ MEDIUM < 60 ≤ HIGH. Labelled a heuristic, never a probability.
- Observed predictions feed the existing `observed_prediction` risk factor: when the observed count changes, the
  incident is re-scored in the same transaction (new revision, audited).
- Watch-signal conditions use the rule-DSL field grammar in `app/prediction/signals.py`, which A3 reuses. String
  matching is case-insensitive; the field and operator sets are allowlists.
- Predictions of merged incidents, or whose predecessors are no longer active (e.g. suppressed), are deleted and
  audited as `prediction.withdrawn`.
- `prediction.explain` never changes scores. An AI candidate must be a catalog technique that is not already predicted
  and must cite valid evidence; it is shown as "AI candidate", unscored and not watched.

## D-027 — Rule DSL, safety and lifecycle (A3)
- Custom rules are JSON validated by Pydantic (`extra="forbid"`) and evaluated by `app/rules/dsl.py`; nothing in a rule
  is ever executed. Conditions reuse the prediction condition grammar (`app/prediction/signals.py`), so watch signals
  and rules share one field/operator allowlist; string comparisons are case-insensitive.
- Regular expressions go through `app/detection/safe_regex.py`: at most 200 characters, and no backreferences,
  lookarounds, nested quantifiers with an unbounded side, or alternation inside an unbounded repeat (Python's `re`
  has no timeout). Values are clipped to 4,096 characters before matching.
- A rule fires per `group_by` group when a sliding window reaches a count or distinct-count threshold, or when an
  ordered `sequence` completes within the window. Detections are identical in shape to built-in ones.
- IDs are `CUS-NNN` and can never shadow a built-in rule. Rules carry versions: editing creates a new version and
  sets the rule back to DRAFT, while the previously activated version keeps running until the new one is activated
  (`active_version` is separate from `current_version`).
- Lifecycle DRAFT → TESTED (a backtest of the current version) → APPROVED → ACTIVE, plus DISABLED and RETIRED.
  Approval needs `rules.approve`, and in two-person mode someone other than the version's author.
- Backtests regroup stored events into the same components the pipeline would build, and also run the rule against
  the synthetic benign day; they report overlap with existing rules, matches inside false-positive incidents and an
  estimated alert rate, all labelled heuristics.
- Built-in rules that declare `TUNABLE` accept threshold/window overrides via `with_parameters`, which A5 uses; the
  engine re-reads overrides and active custom rules on every evaluation.
- `rules.draft` output is rejected unless it validates *and* fires on the incident it was drafted from; otherwise the
  deterministic draft (dominant event kind, shared behaviour, observed threshold) is used.
- Sigma export is best effort and marked as such: thresholds, windows and sequences are not representable in basic
  Sigma, so the export carries warnings and the AEGIS JSON stays the source of truth.

## D-028 — Tuning from false positives (A5)
- Suggestions are deterministic. AEGIS proposes one only when a rule has at least three incidents closed as
  FALSE_POSITIVE that share an entity which appears in no open or resolved incident for that rule. Entities analysts
  marked benign rank first, then the most specific type (source IP before user before asset).
- Built-in rules get a scoped suppression (or a maintenance window when every verdict was `maintenance_window`);
  custom rules get an exclusion condition, which becomes a new rule version. Threshold changes are suggested only
  when every true-positive alert stays above the proposed value.
- Every suggestion is simulated over stored events before it is shown and again at approval. Alerts are compared per
  component by group key. "True positive" means an alert in an incident not closed as FALSE_POSITIVE — open
  incidents included — which is deliberately conservative.
- Approval needs `tuning.approve`; a protected rule (`AEGIS_PROTECTED_RULES`, default LOG-001 and FILE-001) and any
  change that removes true-positive alerts each need an explicit acknowledgement. Two-person mode forbids approving
  your own suggestion.
- Suppressions carry a mandatory expiry of at most 90 days, and expire through a delayed job. Suppressed detections
  are kept with status SUPPRESSED and their suppression ID, never deleted, and stay searchable.
- Applying or reverting re-evaluates affected incidents in the same transaction. Suppressions touch only incidents
  with that rule's detections; threshold, window and exclusion changes re-evaluate every open incident, because they
  can make a rule start firing again where it currently has no detection.
- `tuning.suggest` only ranks and explains; it never changes a scope or an impact figure, and a deterministic ranking
  by impact is used when the LLM is unavailable.

## D-029 — CERT-In drafts (I1)
- **The shipped template is UNVERIFIED.** `data/compliance/cert_in.json` holds the field list, incident categories and
  the six-hour window drafted from general knowledge, not from the official directions. Nothing is hardcoded in code,
  the banner appears in the UI and in every export, and the template hash is stored on each report. Verify it with
  compliance or legal, then set `status`, `verified_against` and `verified_on`.
- Every field records provenance — `profile`, `auto`, `ai`, `human` or `missing` — plus the evidence event IDs or
  AEGIS record references it came from. Impact and reporter notes are human-only; AEGIS cannot judge business impact.
- Drafts are created deterministically so they work with the LLM disabled. When a provider is configured,
  `report.cert_in_narrative` rewrites only the description from the F2 story and is accepted only if it cites valid
  evidence and repeats no instruction-like text; it lands as a new version and never touches a report already in
  review.
- Reportability is a suggestion scored from the rules and techniques that fired and from keywords in AEGIS's own
  detection summaries. Raw event text is never scored: it is attacker-controlled and must not steer a compliance
  decision. The output always carries "confirm with compliance or legal".
- The deadline counts from the first detection time, is stored in UTC and is shown in UTC or IST. States are warning
  at half the window and critical at a quarter.
- Workflow DRAFT → IN_REVIEW → APPROVED → MARKED_SUBMITTED. Review and approval need every required field; approval
  needs `reports.finalize` and, in two-person mode, someone other than the drafter. Marking submitted only records a
  human's own submission time and reference: **AEGIS never transmits a report**, which a test enforces by keeping the
  reports package free of any network import.
- Editing is limited to human fields and the description; evidence-filled fields are regenerated, never typed over.
  Every change creates a version, so drafts can be diffed and audited.

## D-030 — Hardening choices (Phase 7)
- **Metrics are descriptive, not accuracy.** The Metrics page and `make eval` report counts and shares of AEGIS's own
  records (predictions observed, false-positive verdicts, AI grounding, cache hits). They are not precision, recall or
  a benchmark, and the labels say so. The page only shows cards for enabled features.
- **Evaluation covers workflows, not just scenarios.** Besides the eight scenarios it runs three cross-feature checks
  end to end: a rule drafted from lateral-movement backtests on its own incident, three scanner false positives
  produce a scoped suppression with no true-positive loss, and a CERT-In draft fills and cites every automatic field
  while flagging the missing profile.
- **No separate cache pre-warming.** Stories, prediction explanations and CERT-In narratives are already precomputed
  by the incident-change hooks with debounce and supersession, so adding a warming pass would only duplicate jobs.
- **Containers: two images, loopback only.** An API image (uvicorn) and an nginx image that serves the built UI and
  proxies `/api` with buffering off so SSE still streams. The compose file binds to 127.0.0.1 and keeps the database
  in a named volume; no secret is baked into an image. These files are **unverified** — Docker was not available on
  the build machine — and the README and FEATURES say so rather than implying they were tested.
- **Seeding is synthetic and repeatable.** `scripts/seed.py` runs demo scenarios, closes the scanner runs as false
  positives, drafts a rule and a CERT-In report and saves an organisation profile, so a fresh checkout has something
  to walk through. Each run uses fresh asset suffixes, so it can be run repeatedly.
