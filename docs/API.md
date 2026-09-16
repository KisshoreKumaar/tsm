# API reference

All routes live under `/api`. There are 105 of them; every one declares exactly one permission guard, which
`backend/tests/core/test_rbac_matrix.py` checks for every role on each test run.

## Conventions

- **Auth:** `Authorization: Bearer <token>` on everything except `GET /api/healthz`. Missing or wrong token → 401;
  wrong role → 403. `*authenticated` below means any valid identity, including the ingest role.
- **Requests:** JSON only, parsed strictly. Unknown fields are rejected (`extra="forbid"`), lengths are bounded, and
  the batch endpoint has its own larger body limit.
- **Errors:** `{"error": {"code", "message", "details"}}`. Messages never echo submitted values or stack traces.
- **Feature flags:** a disabled feature is not mounted, so its routes return 404 and it disappears from
  `GET /api/me`. The flag column below is the id you put in `AEGIS_FEATURES`.
- **Live data:** `GET /api/stream` (all topics, ids only) and `GET /api/jobs/{id}/stream` (one job's progress and
  streamed tokens) are Server-Sent Events. The browser reads them with `fetch`, so the token stays in the header.
- **OpenAPI:** with `AEGIS_EXPOSE_DOCS=true` (default), Swagger UI is at `/api/docs` and the schema at
  `/api/openapi.json`.

## Core platform (`core`, always on)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/healthz` | public |
| GET | `/api/me` | authenticated |
| GET | `/api/features` | authenticated |
| GET | `/api/overview` | read |
| POST | `/api/events` · `/api/events/batch` | ingest |
| GET | `/api/events` · `/api/events/{event_id}` · `/api/event-kinds` | read |
| GET | `/api/incidents` · `/api/incidents/{incident_id}` | read |
| PATCH | `/api/incidents/{incident_id}` | investigate |
| POST | `/api/incidents/{incident_id}/notes` | investigate |
| GET | `/api/responses` · `/api/responses/{response_id}` · `/api/playbooks` · `/api/endpoints` | read |
| POST | `/api/responses` | respond.recommend |
| POST | `/api/responses/{response_id}/approve` · `/reject` | respond.approve |
| POST | `/api/responses/{response_id}/execute` | respond.execute |
| GET | `/api/rules` · `/api/attack/techniques` | read |
| GET | `/api/audit` · `/api/audit/verify` | read |
| GET | `/api/audit/checkpoint` | audit.export |
| GET | `/api/demo/scenarios` · `/api/demo/runs/{run_id}` | read |
| POST | `/api/demo/run` | ingest |
| GET | `/api/jobs/{job_id}` | read |
| GET | `/api/stream` | read |

Incident updates are revision-checked: send the revision you loaded, or you get 409 `stale_revision`. Closing as
`FALSE_POSITIVE` requires a reason category and a note. Any incident change cancels pending response requests.

## F1 — correlation (`f1`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/campaigns` · `/api/campaigns/{campaign_id}` | read |
| GET | `/api/incidents/{incident_id}/related` | read |
| GET | `/api/entities/{entity_type}/{value}` | read |
| GET | `/api/graph` | read |

## F2 — alert story (`f2`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/incidents/{incident_id}/story` · `/story.md` | read |
| POST | `/api/incidents/{incident_id}/story/regenerate` | ai.use |
| GET | `/api/campaigns/{campaign_id}/story` · `/story.md` | read |

## F3 — AI analyst (`f3`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/analyst/quick-prompts` · `/api/chats` · `/api/chats/{chat_id}` | read |
| POST | `/api/chats` · `/api/chats/{chat_id}/messages` | ai.use |
| POST | `/api/chats/{chat_id}/messages/{message_id}/add-to-notes` | investigate |

Posting a message returns 202 with a job id, a queue position and an ETA; the answer arrives over the job stream.

## F4 — prediction and watchlist (`f4`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/incidents/{incident_id}/predictions` | read |
| POST | `/api/incidents/{incident_id}/predictions/explain` | ai.use |
| GET | `/api/predictions` · `/api/metrics/prediction-hit-rate` · `/api/attack/transitions` | read |

## A3 — detection engineering (`a3`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/rules/custom` · `/api/rules/{rule_id}` · `/api/rules/{rule_id}/export` · `/diff` | read |
| POST | `/api/rules` · `/api/rules/validate` · `/api/rules/{rule_id}/versions` · `/backtest` | rules.draft |
| POST | `/api/rules/draft-from-incident/{incident_id}` | rules.draft |
| POST | `/api/rules/{rule_id}/approve` · `/activate` · `/disable` · `/retire` | rules.approve |

`export?format=json|sigma` returns a file; Sigma is best effort and carries warnings.

## A5 — false-positive tuning (`a5`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/tuning/fp-analytics` · `/api/tuning/suggestions` · `/{suggestion_id}` | read |
| GET | `/api/tuning/suppressed-detections` · `/api/suppressions` | read |
| POST | `/api/tuning/suggestions` · `/generate` · `/{suggestion_id}/simulate` | tuning.draft |
| POST | `/api/tuning/suggestions/{suggestion_id}/approve` · `/reject` · `/revert` | tuning.approve |
| POST | `/api/suppressions/{suppression_id}/revert` | tuning.approve |

Approving returns 422 when a protected rule or a true-positive loss has not been acknowledged.

## I1 — CERT-In drafts (`i1`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/org-profile` · `/api/compliance/deadlines` · `/api/cert-in` | read |
| PUT | `/api/org-profile` | settings.manage |
| GET | `/api/cert-in/{report_id}` · `/export` · `/diff` · `/api/incidents/{incident_id}/cert-in` | read |
| POST | `/api/incidents/{incident_id}/cert-in` | reports.draft |
| PATCH | `/api/cert-in/{report_id}` | reports.draft |
| POST | `/api/cert-in/{report_id}/submit-review` | reports.draft |
| POST | `/api/cert-in/{report_id}/approve` · `/mark-submitted` | reports.finalize |

`export?format=md|json|html&redact=true` returns a file. AEGIS never transmits a report.

## X1 — AI providers (`x1`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/ai/status` · `/api/jobs/{job_id}/stream` | read |
| GET | `/api/llm/providers` · `/api/llm/presets` | llm.configure |
| POST | `/api/llm/providers` · `/api/llm/active` · `/api/llm/providers/{id}/test` | llm.configure |
| PATCH/DELETE | `/api/llm/providers/{provider_id}` | llm.configure |
| PUT/DELETE | `/api/llm/providers/{provider_id}/key` | llm.configure |

API keys are write-only: responses carry `key_set` and the last four characters, never the key.

## X2 — agent console (`x2`)

| Method | Path | Permission |
|---|---|---|
| GET | `/api/agent/tools` · `/api/agent/proposals` | read |
| POST | `/api/agent/proposals/{proposal_id}/apply` | authenticated, then the target action's permission |
| POST | `/api/agent/proposals/{proposal_id}/dismiss` | ai.use |

Apply re-checks the applying human's permission for the proposed action and the target's revision: 403 without the
permission, 409 `stale_proposal` if the target moved, 422 if injection context has not been acknowledged.
