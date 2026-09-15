-- 0001_platform: metadata, tamper-evident audit log, persisted jobs.
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit_log (
    seq          INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    action       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    subject_type TEXT,
    subject_id   TEXT,
    body         TEXT NOT NULL,
    prev_digest  TEXT NOT NULL,
    digest       TEXT NOT NULL UNIQUE
);
CREATE INDEX ix_audit_action ON audit_log(action);
CREATE INDEX ix_audit_subject ON audit_log(subject_type, subject_id);
CREATE INDEX ix_audit_actor ON audit_log(actor);

-- Defence in depth: the application never updates or deletes audit records.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TABLE jobs (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    lane             TEXT NOT NULL CHECK (lane IN ('default', 'ai')),
    status           TEXT NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    priority         INTEGER NOT NULL DEFAULT 100,
    dedup_key        TEXT,
    subject_type     TEXT,
    subject_id       TEXT,
    subject_revision INTEGER,
    payload          TEXT NOT NULL,
    result           TEXT,
    error            TEXT,
    progress         TEXT,
    actor            TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    run_after        TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    started_at       TEXT,
    finished_at      TEXT
);
CREATE INDEX ix_jobs_ready ON jobs(lane, status, priority, run_after, created_at);
CREATE INDEX ix_jobs_dedup ON jobs(dedup_key, status);
CREATE INDEX ix_jobs_subject ON jobs(subject_type, subject_id, created_at);
