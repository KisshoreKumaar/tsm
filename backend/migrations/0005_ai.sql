-- 0005_ai: LLM providers (X1), AI call log and cache, analyst chats (F3), agent proposals (X2).
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE llm_providers (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    preset            TEXT,
    api_type          TEXT NOT NULL CHECK (api_type IN ('ollama', 'openai')),
    base_url          TEXT NOT NULL,
    model             TEXT NOT NULL,
    key_ciphertext    TEXT,
    key_hint          TEXT,
    context_tokens    INTEGER NOT NULL,
    max_output_tokens INTEGER NOT NULL,
    timeout_seconds   REAL NOT NULL,
    json_mode         INTEGER NOT NULL DEFAULT 1 CHECK (json_mode IN (0, 1)),
    redact            INTEGER NOT NULL DEFAULT 1 CHECK (redact IN (0, 1)),
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    priority          INTEGER NOT NULL DEFAULT 100,
    is_active         INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    last_test         TEXT,
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE INDEX ix_llm_providers_order ON llm_providers(enabled, is_active, priority);

CREATE TABLE ai_calls (
    id                TEXT PRIMARY KEY,
    job_id            TEXT,
    task              TEXT NOT NULL,
    provider_id       TEXT NOT NULL,
    model             TEXT NOT NULL,
    prompt_version    TEXT NOT NULL,
    prompt_hash       TEXT NOT NULL,
    input_tokens      INTEGER NOT NULL DEFAULT 0,
    output_tokens     INTEGER NOT NULL DEFAULT 0,
    latency_ms        INTEGER NOT NULL DEFAULT 0,
    ttft_ms           INTEGER,
    tokens_per_second REAL,
    outcome           TEXT NOT NULL CHECK (outcome IN ('valid', 'repaired', 'failed_validation', 'provider_error', 'disabled', 'cache_hit')),
    claims_total      INTEGER NOT NULL DEFAULT 0,
    claims_grounded   INTEGER NOT NULL DEFAULT 0,
    subject_type      TEXT,
    subject_id        TEXT,
    subject_revision  INTEGER,
    actor             TEXT NOT NULL,
    error             TEXT,
    created_at        TEXT NOT NULL
);
CREATE INDEX ix_ai_calls_created ON ai_calls(created_at);
CREATE INDEX ix_ai_calls_task ON ai_calls(task, outcome);

CREATE TABLE ai_cache (
    cache_key        TEXT PRIMARY KEY,
    task             TEXT NOT NULL,
    subject_type     TEXT,
    subject_id       TEXT,
    subject_revision INTEGER,
    prompt_version   TEXT NOT NULL,
    provider_id      TEXT NOT NULL,
    model            TEXT NOT NULL,
    output           TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
CREATE INDEX ix_ai_cache_subject ON ai_cache(subject_type, subject_id);

CREATE TABLE chats (
    id           TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('incident', 'campaign', 'global')),
    subject_id   TEXT,
    title        TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX ix_chats_subject ON chats(subject_type, subject_id, updated_at);

CREATE TABLE chat_messages (
    id         TEXT PRIMARY KEY,
    chat_id    TEXT NOT NULL REFERENCES chats(id),
    role       TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    mode       TEXT NOT NULL CHECK (mode IN ('quick', 'deep', 'agent')),
    content    TEXT NOT NULL,
    job_id     TEXT,
    status     TEXT NOT NULL CHECK (status IN ('pending', 'complete', 'failed')),
    actor      TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX ix_chat_messages_chat ON chat_messages(chat_id, created_at);

CREATE TABLE agent_proposals (
    id                  TEXT PRIMARY KEY,
    chat_id             TEXT REFERENCES chats(id),
    message_id          TEXT,
    job_id              TEXT,
    action              TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    target_id           TEXT,
    target_revision     INTEGER,
    required_permission TEXT NOT NULL,
    payload             TEXT NOT NULL,
    rationale           TEXT NOT NULL,
    evidence_ids        TEXT NOT NULL,
    injection_context   INTEGER NOT NULL DEFAULT 0 CHECK (injection_context IN (0, 1)),
    status              TEXT NOT NULL CHECK (status IN ('PROPOSED', 'APPLIED', 'DISMISSED', 'STALE', 'FAILED')),
    result              TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    decided_by          TEXT,
    decided_at          TEXT,
    decision_note       TEXT
);
CREATE INDEX ix_agent_proposals_status ON agent_proposals(status, created_at);
CREATE INDEX ix_agent_proposals_target ON agent_proposals(target_type, target_id);
