# AEGIS SOC — Build Prompt for Claude Code

> **How to use**
> 1. Fill in every `[BRACKET]` in Section 0.
> 2. Create an empty folder, run `git init`, start Claude Code there.
> 3. Paste everything below the horizontal line as your first message.
> 4. To add a feature at any point, type `NEW FEATURE: <description>` (see Section 9).

---

# Build AEGIS SOC — an AI-assisted Security Operations workbench

## 0. Project context

- **Project:** AEGIS SOC
- **Purpose:** Hackathon entry — [HACKATHON NAME]; zonal round on [DATE]; grand finale on [DATE]
- **Target awards:** Best AI Innovation, Best Industry Solution, Best Startup Potential, National Champion
- **Team:** [N people and who owns backend / frontend / AI / demo]
- **LLM server:** self-hosted on Amazon EC2, OpenAI-compatible API at [BASE URL] using [vLLM / llama.cpp / Ollama], model [MODEL NAME], measured about [3.8] tokens/second. Assume it is **slow and can be unavailable**.
- **Reference prototype (optional, read-only):** [/Users/apple/Developer/gpt/claude/aegis-soc]. You may read it for ideas (strict validation, audit hash chain, approval flow, synthetic scenarios). Do not copy its structure. Known prototype bug to avoid: attack stages were ordered by rule-evaluation order instead of event time.

## 1. Your role and working rules

You are the lead engineer. Follow these rules for the whole build:

1. **Plan first.** Read this entire prompt, then enter plan mode and present: architecture, repository layout, data model, API route list, permission matrix, phase breakdown with acceptance criteria, and open questions. **Write no code until I approve the plan.**
2. **Build in phases** (Section 8). Every phase ends at a **CHECKPOINT**: tests pass, lint and type checks pass, demo steps work, work is committed, then you **stop and ask whether I want to add or change features** before the next phase.
3. **`docs/FEATURES.md` is the source of truth for scope.** Every feature has an ID, status (`planned`, `in-progress`, `done`, `backlog`, `skipped`), phase, and acceptance criteria. Keep it current.
4. **Never silently expand or cut scope.** For small ambiguities, choose a sensible default, record it in `docs/DECISIONS.md`, and continue.
5. **Verify, don't assume.** Write tests with the code. Only mark something done after running the tests and seeing them pass. Report failures and skipped items honestly.
6. **Git:** one branch per phase, small commits per completed unit, clear messages. Never commit secrets.
7. **Keep `CLAUDE.md` updated** with commands, conventions, and the invariants in Section 10 so a fresh session can resume from `CLAUDE.md` + `docs/FEATURES.md` alone.

## 2. Product summary

AEGIS ingests security telemetry, detects known attack patterns, correlates alerts into incidents and campaigns, tells the **alert story**, predicts **likely next attacker steps**, and gives analysts an **AI analyst** that answers questions with cited evidence. It helps detection engineers **draft and test new rules**, **learns from false positives** to suggest safe tuning, and drafts **CERT-In incident reports** against the reporting deadline. Containment actions are simulated behind human approval, and everything is audited.

### Features in scope

| ID | Feature |
|---|---|
| CORE | Ingestion, detection, risk scoring, incidents, simulated response, RBAC, audit, demo scenarios, UI shell |
| F1 | Alert correlation (incidents + campaigns, explained links) |
| F2 | Alert story (chronological, cited narrative) |
| F3 | AI analyst (grounded Q&A agent with read-only tools) |
| F4 | Attack prediction and next-step prediction, with a watchlist that detects when a prediction comes true |
| A3 | AI detection engineer (draft rule → backtest → approve → activate) |
| A5 | Learning from false positives (tuning suggestions with impact simulation) |
| I1 | CERT-In incident report drafts with deadline tracking |

### Product principles

- **Evidence first:** every conclusion links to event IDs.
- **AI advises, humans decide:** AI has no write authority. Every AI output is a draft until a human with the right role accepts it.
- **Deterministic core:** detection, correlation, story skeleton, scoring and prediction work without the LLM. AI enhances them. The app must be fully usable when the LLM is disabled or down.
- **Log content is untrusted data**, never instructions.
- **Simulated response only.** No real endpoint changes. No automatic submission to any external agency.
- **Everything auditable.**

## 3. Tech stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2, SQLite in WAL mode via `sqlite3` with numbered SQL migrations, `httpx` for the LLM client, `pytest` (+ `hypothesis` for property tests), `ruff`, `mypy` (lenient is fine).
- **Frontend:** React + TypeScript (strict) + Vite. A small component library is fine. Graph view with Cytoscape.js or React Flow. No runtime CDN assets.
- **Jobs:** in-process background worker backed by a persisted `jobs` table, with restart recovery.
- **Streaming:** Server-Sent Events for AI output and live updates.
- **Packaging:** Docker Compose (api + web), `.env.example`, GitHub Actions CI (lint, type check, backend tests, frontend build), a `Makefile` or `justfile` with `dev`, `test`, `lint`, `eval`, `demo` targets.
- Keep dependencies minimal and pinned. If a different choice is clearly better, propose it in the plan with reasons. Do not switch stacks mid-build.

## 4. Architecture for extensibility (required)

New features must be addable without rewriting core code.

### Repository layout (adjust in the plan if needed)

```text
backend/
  app/
    core/          config, db, migrations runner, auth + RBAC, audit chain, jobs, feature registry, SSE
    ingest/        event schemas, event-kind registry, normalization, entity extraction, dedup
    detection/     Rule protocol, built-in rules, rule DSL engine, backtest engine
    correlation/   incident correlation, campaign correlation, link reasons
    story/         deterministic story builder
    prediction/    ATT&CK catalog loader, transition model, scoring, watchlist
    ai/            provider interface, guardrails, citation validator, injection detector,
                   tasks/ (one module per AI task), prompts/ (versioned templates)
    features/      one package per feature: router.py, service.py, models.py, tests/
    reports/       incident report, cert_in/
    demo/          synthetic scenarios + staged replay
  migrations/      0001_init.sql, 0002_..., append-only
  data/            attack/techniques.json, attack/transitions.json, compliance/cert_in.json
  tests/
frontend/
  src/core/        api client, auth, layout, SSE
  src/features/<feature>/   pages, components, api
  src/featureManifest.ts    nav + routes built from enabled features
scripts/           evaluate.py, generate_scenario.py, ingest.py, manage.py (token, backup, verify-audit)
docs/              FEATURES.md, DECISIONS.md, ADDING_A_FEATURE.md, ARCHITECTURE.md, API.md, SECURITY.md, DEMO.md
```

### Extension points

- **Feature registry + flags:** each feature declares `id`, `name`, `depends_on`, API router, background job handlers, audit action names, and a frontend manifest entry. Enabled via config (`AEGIS_FEATURES`). A disabled feature hides its UI and its routes return 404.
- **Event-kind registry:** a new event kind declares its Pydantic schema and entity extraction without edits to core ingestion.
- **Rule protocol:** built-in Python rules and DSL rules share one interface: `id`, `name`, `version`, `techniques`, `evaluate(events) -> list[Detection]`.
- **AI task registry:** each task declares a versioned prompt template file, input builder, Pydantic output schema, validator, deterministic fallback, and token budget.
- **Migrations are append-only.** Never edit an applied migration.
- **`docs/ADDING_A_FEATURE.md`:** a step-by-step checklist (feature package, registry entry, flag, migration, permissions, audit actions, tests, UI module, FEATURES.md, docs). Keep it accurate as the code evolves.

## 5. Core platform (Phase 1)

### 5.1 Ingestion

- `POST /api/events` (single) and `POST /api/events/batch` (1–500 events, configurable, atomic: one invalid event rolls back the batch). CLI ingester for JSON/JSONL.
- Fields: `event_id`, `source`, `timestamp`, `asset`, `user`, `kind`, `source_ip`, `destination_ip`, `destination_port`, `domain`, `process_name`, `parent_process`, `command_line`, `file_path`, `file_hash`, `details`, `criticality` (1–5), `privileged` (bool).
- Kinds: `auth_failure`, `auth_success`, `process_start`, `network_connection`, `file_change`, `user_created`, `privilege_change`, `log_cleared`, `suspicious_process`, `malicious_indicator`, with required fields per kind.
- Strict validation: unknown fields rejected, duplicate JSON keys rejected, typed IPs and ports, length limits, timezone-aware timestamps not later than now + configurable clock-skew tolerance (default 2 minutes), stored in UTC.
- Store the submitted raw JSON and the normalized event.
- Idempotent dedup on `(source, event_id)` using a canonical-JSON digest: identical retry returns the original; same ID with different content is rejected.

### 5.2 Built-in detection rules

Each rule has unit tests for positive, negative and edge cases. Technique IDs must exist in the local ATT&CK catalog (Section F4).

| Rule | Logic | Candidate technique |
|---|---|---|
| AUTH-001 | ≥5 failures in a 10-minute sliding window per asset + user + source + source IP | T1110 |
| AUTH-002 | Success following AUTH-001 in the same context | T1078 |
| PROC-001 | PowerShell (`powershell`, `pwsh`, with or without `.exe`/path) with `-e`, `-ec`, or any prefix of `-EncodedCommand`, using `-` or `/` | T1059.001 |
| NET-001 | ≥10 distinct destination IP:port pairs in 5 minutes per asset + user | T1046 |
| FILE-001 | ≥50 file changes in 2 minutes on one asset (possible ransomware) | T1486 |
| LOG-001 | Security log cleared | T1070.001 |
| ACCT-001 | New user created or privilege change | T1136 / T1098 |
| INJ-001 | Event fields contain instruction-like text aimed at AI (see Section 7) | none |
| SOURCE-001/002 | Upstream suspicious process / malicious indicator alert | none (never invent a mapping) |

### 5.3 Risk scoring

Explainable: a capped sum of named factors (threat severity, detection confidence, asset criticality, privilege, attack progression, event count, reported indicator, potential impact, observed prediction). Return every factor. Severity bands LOW / MEDIUM / HIGH / CRITICAL. Always label it a heuristic, never a probability.

### 5.4 Incidents

Statuses `OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, `MERGED`. Owner, notes, optimistic revision checks (stale updates rejected), closing requires a note, new correlated evidence reopens closed incidents. Claims are labeled `FACT`, `INFERENCE`, `HYPOTHESIS`, `UNKNOWN`.

### 5.5 Simulated response

Allowlisted playbooks: isolate endpoint, restore connectivity, collect evidence manifest (SHA-256 per event). Flow: recommend → approve (explicit confirmation text, bound to incident revision, 15-minute expiry, optional two-person rule that forbids the requester from approving **or executing**) → execute (update virtual endpoint registry, read back, verify) → or reject with a reason. Any incident change cancels pending/approved requests. Execution cannot repeat.

### 5.6 Auth and RBAC

Named token identities (store token hashes, constant-time compare, tokens only in the `Authorization` header). Roles and permissions (refine in the plan):

| Role | Permissions |
|---|---|
| viewer | read |
| ingest | ingest (receives only IDs back) |
| analyst | read, ingest, investigate, ai.use, respond.recommend, reports.draft |
| detection_engineer | read, ai.use, rules.draft, tuning.draft |
| approver | read, respond.approve, respond.execute, rules.approve, tuning.approve, reports.finalize |
| admin | all |

Enforce on every route and test the full matrix. Per-client rate limiting, request body limits, security headers, strict CORS, no stack traces in responses.

### 5.7 Audit

Every successful state change appends an audit record **in the same transaction**. HMAC-SHA256 hash chain keyed by `AEGIS_AUDIT_KEY`. Verify endpoint, verification at startup (refuse to start on a broken chain or wrong key), checkpoint export of the chain head, consistent SQLite backup command.

### 5.8 Synthetic demo scenarios

Every run uses a unique synthetic asset suffix. Two modes: `instant` and `replay` (events released on a timer, e.g. every 5–10 seconds, so predictions and correlation can be shown live).

| Scenario | Purpose |
|---|---|
| attack-chain | Brute force → success → encoded PowerShell → port scan: one incident |
| benign | Normal activity: zero incidents |
| late-arrival | Same as a chain but out of order: identical result |
| indicator | Upstream alert: incident without invented technique |
| lateral-movement | Same user and source IP across 3 hosts: 3 incidents in 1 campaign |
| authorized-scanner | Repeated NET-001 hits from a known scanner IP: false-positive learning |
| ransomware-burst | Mass file changes + log clearing |
| prompt-injection | Log fields containing instructions aimed at the AI |

### 5.9 UI shell

Token login (kept in memory only, lock button), overview metrics, incident queue with search/filter/pagination, incident page (timeline, detections, risk factors, notes, response request), events explorer, responses page, audit page with verify and export.

## 6. Feature specifications

### F1 — Alert correlation

**Goal:** group related events into incidents, and related incidents into campaigns, with every link explained.

Requirements:
1. Entity extraction per event: asset, user, source IP, destination IP, domain, file hash, process. Normalize case where appropriate.
2. **Incident correlation (tight):** same asset + user within a sliding window (default ±10 minutes, configurable), chaining as events arrive. Late events re-evaluate both sides. When incidents join, the oldest stays canonical, others become `MERGED`, their responses are cancelled, and it is audited.
3. **Campaign correlation (loose):** link incidents sharing an entity within a window (default 24 hours): same user on different assets, same external source IP across assets, same destination IP / domain / file hash across assets.
4. A configurable **common-entity allowlist** (e.g. DNS servers, jump hosts, `SYSTEM`) plus a maximum link degree to prevent over-linking.
5. Each link stores its reason: link type, shared entity value, time delta, supporting event IDs, and a link strength.
6. Campaigns have their own risk, affected assets/users, and combined timeline.
7. Results must be identical regardless of event arrival order. Capacity caps fail atomically.

API: `GET /api/campaigns`, `GET /api/campaigns/{id}`, `GET /api/incidents/{id}/related`, `GET /api/entities/{type}/{value}`.
UI: correlation graph (incidents, assets, users, IPs as nodes; edges labeled with reasons), campaign page, related-incidents panel.

Acceptance:
- attack-chain → exactly 1 incident; benign → 0.
- Property test: random permutations of scenario events produce the same incidents and campaigns.
- lateral-movement → 3 incidents in 1 campaign, with reasons naming the shared user and source IP.
- Allowlisted entities do not create links. Merges cancel responses and are audited.

### F2 — Alert story

**Goal:** turn an incident or campaign into a chronological, cited narrative.

Requirements:
1. **Deterministic story builder (always available):** stages ordered by their earliest evidence timestamp. Each stage has tactic, candidate technique, start/end time, event IDs, rule IDs, and a template sentence with concrete values (counts, IPs, ports, process names).
2. Two formats, both cited:
   - **Analyst:** technical, 150–300 words.
   - **Executive:** plain language, five lines: what happened, impact, whether contained, what we are doing, what we need.
3. **AI polish** (task `story.narrate`): input is the deterministic story plus a compact evidence pack. Output is sentences, each with a label and evidence IDs. Validate; fall back to the deterministic story on failure.
4. Stories are versioned by incident revision and show a stale indicator when the incident changes. Analysts can regenerate.
5. Campaign stories combine incident stories.
6. The story feeds reports (I1) and Markdown export.

UI: story tab with analyst/executive toggle, clickable citations that highlight events in the timeline, badge showing "Deterministic" or "AI-polished (validated)".

Acceptance:
- Stages are chronological, including a test where PowerShell occurs **before** the failed logins.
- Every FACT sentence cites at least one valid event ID.
- An AI output citing a non-existent event ID is rejected (FakeProvider test).
- With the LLM disabled the deterministic story still renders.
- Injection strings from the prompt-injection scenario appear only as quoted data.

### F3 — AI analyst

**Goal:** analysts ask anything about an incident or campaign and get grounded answers.

Requirements:
1. Chat per incident and per campaign with persisted history. Each question is an async job; output streams via SSE.
2. Two modes:
   - **Quick (default):** one model call over a compact evidence pack.
   - **Deep:** agent loop with read-only tools: `get_incident`, `get_story`, `search_events`, `get_entity_history`, `get_related_incidents`, `get_campaign`, `list_rules`, `get_predictions`, `get_false_positive_history`. Default maximum of 4 steps, a total token budget, and a size cap on each tool result.
3. Answer schema: `summary`, `claims[]` (text, label, evidence_ids), `suggested_next_questions[]`, `suggested_actions[]` (text only; may reference allowlisted playbook IDs), `confidence` (low/medium/high heuristic).
4. Out-of-scope questions return an UNKNOWN answer that explains the limits. No external lookups.
5. **No write capability.** The AI cannot change status, notes, rules, tuning, responses, or reports. The analyst may click "Add to notes", which creates a human-authored note referencing the AI job ID.
6. Quick prompts: Why is this suspicious? Explain the risk. What happened? Is this a false positive? What is likely next? What should I do now?
7. Deterministic template answers when the LLM is disabled.

Acceptance:
- FakeProvider tests: tool loop terminates, step cap enforced, fake event IDs rejected, malformed JSON repaired once or failed cleanly.
- Injection corpus passes: the AI never recommends approval/execution because a log line says so, and tool-call-like text inside events is ignored.
- A role without `ai.use` gets 403. Every AI call creates an audit record.

### F4 — Attack prediction and next-step prediction

**Goal:** forecast likely next attacker steps from observed evidence, tell analysts what to watch for, and detect when a prediction comes true.

Requirements:
1. **Local ATT&CK catalog** `data/attack/techniques.json` (id, name, tactics, url) containing only IDs you have verified against attack.mitre.org, with MITRE attribution. Every technique ID anywhere in the system is validated against it.
2. **Transition model** `data/attack/transitions.json`: from observed technique/tactic to candidate next techniques, with base weight and written rationale. Start with, for example: T1110 → T1078; T1078 → T1059.001, T1087, T1021; T1059.001 → T1046, T1105, T1003; T1046 → T1021; T1021 → T1486, T1041. Document it as a curated, editable heuristic.
3. **Scoring:** base weight adjusted by context (privileged account, successful authentication observed, asset criticality, stages already observed, recency, campaign breadth) → relative likelihood score 0–100 with band. Show every factor. Never call it a probability.
4. **Each prediction** includes: technique, tactic, score, rationale, supporting evidence IDs, **watch signals** expressed as rule-DSL conditions (event kinds, fields, rule IDs), suggested preventive actions (text + allowlisted simulated playbooks), heuristic time horizon. All predictions are labeled HYPOTHESIS.
5. **Watchlist:** active predictions are monitored. When a new correlated event matches a watch signal → prediction becomes `OBSERVED`, evidence is linked, incident risk rises, the UI shows a live alert, and it is audited. After the horizon → `EXPIRED`.
6. **AI task `prediction.explain`:** plain-language explanation of top predictions. It may propose one extra candidate labeled "AI candidate" only if the technique ID exists in the catalog and the rationale cites evidence. It never changes scores.
7. Metric: prediction hit rate across scenarios (observed / total).

UI: "What's likely next" panel with ranked cards, watch signals, status (`WATCHING`, `OBSERVED`, `EXPIRED`), and timeline markers when a prediction is observed.

Acceptance:
- In attack-chain **replay**, after brute force + success, a prediction for execution appears; when the PowerShell event arrives it flips to `OBSERVED`.
- Invalid technique IDs are rejected. Works with the LLM disabled.

### A3 — AI detection engineer

**Goal:** turn an incident into a new, tested detection rule that a human approves.

Requirements:
1. **Rule DSL** (JSON validated by Pydantic; never executable code): event kinds; field conditions (`equals`, `in`, `contains`, `startswith`, `endswith`, `cidr`, numeric comparisons, restricted `regex` with a 200-character cap and rejection of nested quantifiers and backreferences); `group_by`; `window_seconds`; `threshold` count or `distinct_count(field)`; optional ordered `sequence` (A then B within window); severity; validated technique IDs; description; known false positives.
2. DSL rules run in the same pipeline as built-in rules and emit the same `Detection` objects.
3. **AI task `rules.draft`:** input is the incident evidence pack plus existing rule summaries; output is a DSL rule, rationale and expected false positives. Engineers can also write or edit rules manually with live validation.
4. **Backtest (required before approval):** run over stored events for a chosen time range. Report total matches, incidents that would be created, overlap with existing rules, matches inside incidents closed as FALSE_POSITIVE, matches in benign scenario data, estimated alerts per day, sample hits with event IDs, runtime.
5. **Lifecycle:** `DRAFT → TESTED → APPROVED → ACTIVE → DISABLED/RETIRED`. Editing creates a new version; old versions are kept. With two-person mode the approver must differ from the author. Everything audited.
6. Export as JSON; best-effort Sigma YAML export for simple rules, clearly marked.

UI: Rules page (built-in, custom, drafts), rule editor, "Draft rule from this incident" button, backtest results, version diff.

Acceptance:
- DSL rejects unknown fields and dangerous regex.
- A rule drafted from the lateral-movement incident backtests with at least one hit on that incident.
- A rule cannot become ACTIVE without TESTED + approval. An active rule fires on new ingestion; disabling stops it.
- Invalid AI DSL output is repaired once or fails cleanly.

### A5 — Learning from false positives

**Goal:** learn from analyst false-positive verdicts and suggest safe tuning.

Requirements:
1. Closing as `FALSE_POSITIVE` requires a reason category (`authorized_scanner`, `maintenance_window`, `known_admin_activity`, `user_error`, `test_activity`, `misconfigured_source`, `other`), a note, and optionally the entities believed benign.
2. **False-positive analytics:** counts and rates per rule, entity and source, with trends over time.
3. **Tuning suggestions:** deterministic candidate generation plus AI task `tuning.suggest` for ranking and rationale. Types:
   - scoped suppression (rule + entity values + mandatory expiry, maximum 90 days)
   - threshold change
   - window change
   - DSL exclusion condition (custom rules)
   - maintenance-window schedule
4. **Impact simulation for every suggestion:** alerts that would be removed, and true-positive incidents that would be lost. If any true positive would be lost, flag it red and require explicit acknowledgement.
5. Human approval with `tuning.approve`. Never auto-apply. One-click revert. Audited.
6. Suppressed detections are still stored as `SUPPRESSED` with the suppression ID, visible and searchable, never deleted.
7. A protected-rules list (e.g. LOG-001, FILE-001) requires an extra warning and acknowledgement before any suppression.

UI: Tuning page with false-positive dashboard, suggestion queue, impact view, and active suppressions with expiry countdown.

Acceptance:
- authorized-scanner scenario closed as FALSE_POSITIVE three times → suggestion to suppress NET-001 scoped to the scanner IP, impact shows alerts removed and zero true positives lost.
- After approval, the attack-chain scan from a different IP is still detected.
- Expired suppressions stop applying; revert works; audit records exist.

### I1 — CERT-In incident report drafts

**Goal:** produce a CERT-In incident report draft quickly to help the organization meet India's reporting deadline. A human reviews it and submits it outside the app.

Requirements:
1. **Template config** `data/compliance/cert_in.json`: form fields, incident type list, reportability notes, `verified_against` (source document) and `verified_on` (date). **Do not hardcode CERT-In categories or field lists in code from memory.** Put your best draft in the config, mark it `UNVERIFIED`, and remind the team at the checkpoint to verify it against the current official CERT-In directions and reporting form.
2. **Organization profile** (admin-managed): name, sector, point of contact, address, and similar fields.
3. **Draft generation:**
   - Deterministic mapping: detection time (first detection), occurrence time (earliest evidence), affected systems (assets), indicators (IPs, domains, hashes from evidence), actions taken (response audit history), suggested incident type (from rules/techniques mapping).
   - AI task `report.cert_in_narrative` writes the description from the F2 story.
   - Every field shows its provenance (`auto`, `AI`, `human`) and citations.
4. **Reportability assistant:** suggests whether the incident likely falls into a reportable category, with reasons, labeled "Suggestion — confirm with compliance/legal".
5. **Deadline tracker:** countdown from detection time (configurable hours, default 6) on the incident page and overview, with warning states. Store UTC; display IST option.
6. **Workflow:** `DRAFT → IN_REVIEW → APPROVED` (`reports.finalize`) `→ MARKED_SUBMITTED` (a human records the submission time and reference number manually). **The app never sends anything externally.**
7. Redaction toggle for personal data in exports. Exports: Markdown, JSON, print-friendly HTML.
8. Versioned drafts with diff; audited.

UI: Compliance page listing incidents with deadlines; report editor with provenance badges and highlighted missing required fields.

Acceptance:
- attack-chain incident produces a draft with all automatic fields filled and linked to evidence.
- Missing organization profile is flagged.
- Deadline countdown is correct across time zones.
- Cannot mark submitted without approval.
- A test asserts the reports module makes no network calls.

## 7. Shared AI layer (Phase 3; used by F2, F3, F4, A3, A5, I1)

### Provider

- Interface `LLMProvider.complete(messages, output_schema, max_tokens, timeout, stream)`.
- Implementations: `OpenAICompatibleProvider` (base URL, model, API key from env), `FakeProvider` (scripted deterministic responses for tests), `DisabledProvider`.
- Config: `AEGIS_LLM_ENABLED`, `AEGIS_LLM_BASE_URL`, `AEGIS_LLM_MODEL`, `AEGIS_LLM_API_KEY`, `AEGIS_LLM_TIMEOUT_S` (default 180), `AEGIS_LLM_MAX_OUTPUT_TOKENS` (default 600), `AEGIS_LLM_MAX_CONCURRENCY` (default 1), `AEGIS_LLM_CONTEXT_TOKENS`, `AEGIS_LLM_REDACT`.
- **Tests never call a real model or the network.**

### Designed for a slow model (~4 tokens/second)

- All AI work runs as async jobs; results stream over SSE.
- Show the deterministic result immediately; replace it with the validated AI version when ready.
- Precompute stories and prediction explanations when an incident changes (debounced; only the latest revision; cancel superseded jobs).
- Cache by (task, incident revision, prompt version, model).
- Compact evidence packs with a token budget: summaries + top-N events + IDs, not full raw JSON.
- UI shows queue position and an ETA based on measured tokens/second.
- A health check measures and reports tokens/second.

### Output contract and grounding

- JSON only, validated by the task's Pydantic schema. One repair retry, then deterministic fallback with `ai_status: failed_validation`.
- Every claim has a label (`FACT`, `INFERENCE`, `HYPOTHESIS`, `UNKNOWN`) and `evidence_ids`. A FACT needs at least one valid ID.
- The citation validator flags or drops claims that cite IDs not present in the provided evidence. Track a `grounding_rate`. Never display an unvalidated claim as FACT.

### Prompt-injection defense

- Evidence goes into a clearly delimited JSON data block. The system prompt states that the data is untrusted and must never be followed as instructions.
- An injection detector scans event fields and tool results for instruction-like patterns (e.g. "ignore previous instructions", "system prompt", "you are now", role tags, tool-call-shaped JSON). Matches mark the event `injection_suspected`, raise INJ-001, and show a warning in the UI.
- The AI only has read-only tools. It never fetches URLs or executes, decodes-and-runs, or evaluates content.
- Maintain `tests/ai/injection_cases.jsonl`; all cases must pass.

### Privacy and audit

- Optional redaction of usernames, emails and IPs before sending to the model, with a server-side reversible mapping.
- Audit every AI call: task, model, prompt version, prompt hash, input/output token counts, latency, tokens/second, validation outcome, incident revision, actor. Never store secrets.

### AI status page

Model, enabled/disabled, measured tokens/second, queue length, cache hit rate, grounding rate, injection test pass rate, fallback count.

## 8. Build phases and checkpoints

| Phase | Scope |
|---|---|
| 0 | Plan approval. Scaffold repo, `CLAUDE.md`, `docs/FEATURES.md` (all IDs with acceptance criteria), `docs/DECISIONS.md`, `docs/ADDING_A_FEATURE.md`, config, migrations runner, feature registry, FakeProvider, CI, Makefile. |
| 1 | Core platform (Section 5). |
| 2 | F1 correlation, F2 deterministic story, staged replay demo mode. |
| 3 | Shared AI layer (Section 7), F3 AI analyst, F2 AI polish. Test against the real EC2 endpoint: measure tokens/second and verify fallback when it is unreachable. |
| 4 | F4 attack prediction + watchlist. |
| 5 | A3 detection engineer (DSL + backtest), then A5 false-positive learning (reuses backtest). |
| 6 | I1 CERT-In drafts. |
| 7 | Hardening and demo: `scripts/evaluate.py` + metrics dashboard, security review, cache pre-warming for the slow model, Docker, README, API/OpenAPI, ARCHITECTURE, SECURITY, DEMO (5-minute script), seed data. |

**At every checkpoint, report:**
1. What was built (with feature IDs).
2. Actual test, lint and evaluation results.
3. Step-by-step demo instructions for this phase.
4. Known issues and deviations from the spec.
5. Updated `docs/FEATURES.md` status.
6. Then ask: **"Any new features or changes before Phase N+1?"** and wait.

## 9. Adding features during the build

I may send these commands at any time:

| Command | What you do |
|---|---|
| `NEW FEATURE: <description>` | Follow the protocol below and ask when to build it |
| `NEW FEATURE (now): <description>` | Same protocol, but insert it immediately after the current unit of work |
| `CHANGE: <description>` | Treat as a modification to an existing feature ID; same protocol |
| `STATUS` | Show `docs/FEATURES.md` progress, current phase, next steps, blockers |
| `SKIP: <ID>` | Mark skipped with reason; remove dependencies cleanly |
| `REPRIORITIZE: <instructions>` | Reorder phases/features and update the plan |

**Protocol:**
1. Reach a safe stopping point: finish the current small unit and never leave tests failing.
2. Restate the request, write acceptance criteria, assign an ID (`X1`, `X2`, …), list modules and extension points touched, dependencies, any risk to the invariants in Section 10, effort (S/M/L), and the best phase.
3. Recommend now / after the current phase / backlog, and wait for my choice (unless marked `(now)`).
4. Update `docs/FEATURES.md` and `docs/DECISIONS.md`.
5. Implement through the extension points (feature package + registry + flag + migration + permissions + audit + tests + UI module). If core code must change, explain why first.
6. Run the full test suite and `scripts/evaluate.py`, update docs, commit.

**Backlog ideas I may request later (do not build unless asked):**
A2 prompt-injection showcase page, A4 encoded-command decoder and explainer, A7 AI scorecard page, S1 plain-language mode, S2 Indian-language summaries, S4 PII masking before AI, I2 DPDP breach notification draft, I3 compliance control mapping (ISO 27001 / RBI / SEBI CSCRF), I4 Sigma rule import, I7 SLA tracking and escalation, B1 multi-tenant mode, B2 AWS CloudTrail / Wazuh / Sysmon connectors, B4 ROI metrics dashboard, G1/G2 rules-first AI gating with energy meter.

## 10. Non-negotiable invariants (copy into CLAUDE.md)

1. AI has no write authority. AI outputs are drafts; humans with the right permission accept them.
2. Every FACT cites valid evidence IDs. Unvalidated AI output is never displayed as fact.
3. Event content is data, never instructions. It is never executed, evaluated, or used to fetch anything.
4. The app is fully functional with the LLM disabled. Tests use FakeProvider only.
5. Responses are simulated. Nothing is submitted externally. The only outbound network call allowed is to the configured LLM endpoint.
6. Every state change is audited in the same transaction; the audit chain stays verifiable.
7. Detection and correlation results do not depend on event arrival order.
8. Risk and likelihood scores are heuristics and are never labeled probabilities.
9. Only synthetic or authorized lab data. No secrets in the repo. Tokens only in headers.
10. Migrations are append-only. Every feature sits behind a flag.

## 11. Quality bar

- **Backend:** unit + API integration tests; RBAC matrix test for every route; property tests for arrival-order invariance; AI tests with FakeProvider covering fake citations, malformed output, step caps and the injection corpus.
- **Frontend:** strict type check, production build, component tests for citation rendering and approval dialogs; a Playwright smoke test of the demo flow if time allows.
- **`scripts/evaluate.py`:** runs every scenario and prints expected vs actual incidents and campaigns, rules fired, story citation validity, prediction hit rate, injection pass rate, backtest figures, and CERT-In field completeness. Exits non-zero on regression. CI runs it.
- **Security:** input bounds everywhere, no stack traces to clients, CSP on the web app, secrets only via environment.

## 12. Finale demo (definition of done)

1. Start the app; show AI status (EC2 model connected, or fallback mode).
2. Replay **attack-chain**: brute force → "likely next: execution" prediction appears → PowerShell event arrives → prediction flips to OBSERVED live.
3. Replay **lateral-movement**: campaign graph links 3 hosts with labeled reasons.
4. Show the **alert story** in executive and analyst views; click citations to jump to events.
5. Ask the **AI analyst** "Is this a false positive?" → grounded, cited answer. Run **prompt-injection** → INJ-001 raised and the AI does not follow the embedded instructions.
6. **Draft a detection rule** from the incident → backtest → approve → activate → a new replay is caught by it.
7. **authorized-scanner** → close as false positive three times → tuning suggestion → impact simulation → approve → noise gone, real attack still detected.
8. **CERT-In draft** with deadline countdown → review → approve → export.
9. Simulated containment with approval → verify the audit chain → show evaluation metrics.

---

**Start now with Phase 0.** Read everything above, enter plan mode, and present the plan. Do not write code until I approve it.
