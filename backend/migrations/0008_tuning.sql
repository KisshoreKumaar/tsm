-- 0008_tuning: false-positive tuning suggestions, suppressions and rule parameter overrides (A5).
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE tuning_suggestions (
    id            TEXT PRIMARY KEY,
    type          TEXT NOT NULL CHECK (type IN ('suppression', 'maintenance_window', 'threshold', 'window', 'dsl_exclusion')),
    rule_id       TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('PROPOSED', 'APPROVED', 'REJECTED', 'REVERTED')),
    scope         TEXT NOT NULL,
    rationale     TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    impact        TEXT,
    impact_at     TEXT,
    source        TEXT NOT NULL CHECK (source IN ('deterministic', 'manual')),
    ai_rank       INTEGER,
    ai_rationale  TEXT,
    applied       TEXT,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    decided_by    TEXT,
    decided_at    TEXT,
    decision_note TEXT
);
CREATE INDEX ix_tuning_suggestions_status ON tuning_suggestions(status, updated_at);
CREATE INDEX ix_tuning_suggestions_fingerprint ON tuning_suggestions(fingerprint, created_at);

-- Suppressed detections are never deleted: they stay in `detections` with status SUPPRESSED and this ID.
CREATE TABLE suppressions (
    id            TEXT PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    entities      TEXT NOT NULL,
    schedule      TEXT,
    reason        TEXT NOT NULL,
    suggestion_id TEXT REFERENCES tuning_suggestions(id),
    status        TEXT NOT NULL CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVERTED')),
    expires_at    TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    ended_by      TEXT,
    ended_at      TEXT,
    end_reason    TEXT
);
CREATE INDEX ix_suppressions_rule ON suppressions(rule_id, status, expires_at);

CREATE TABLE rule_parameters (
    id            TEXT PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    parameters    TEXT NOT NULL,
    previous      TEXT NOT NULL,
    suggestion_id TEXT REFERENCES tuning_suggestions(id),
    status        TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'REVERTED')),
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    ended_by      TEXT,
    ended_at      TEXT,
    end_reason    TEXT
);
CREATE INDEX ix_rule_parameters_rule ON rule_parameters(rule_id, status);
