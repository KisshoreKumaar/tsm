-- 0004_story: saved alert-story versions (F2). Deterministic stories are also rebuilt on demand.
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE stories (
    id               TEXT PRIMARY KEY,
    subject_type     TEXT NOT NULL CHECK (subject_type IN ('incident', 'campaign')),
    subject_id       TEXT NOT NULL,
    subject_revision INTEGER NOT NULL,
    version          INTEGER NOT NULL,
    source           TEXT NOT NULL CHECK (source IN ('deterministic', 'ai_polished')),
    ai_status        TEXT NOT NULL,
    content          TEXT NOT NULL,
    prompt_version   TEXT,
    provider         TEXT,
    model            TEXT,
    created_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    UNIQUE (subject_type, subject_id, version)
);
CREATE INDEX ix_stories_subject ON stories(subject_type, subject_id, version);
