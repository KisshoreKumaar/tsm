-- 0007_rules: custom detection rules in the JSON DSL with versions, lifecycle and backtests (A3).
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE dsl_rules (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('DRAFT', 'TESTED', 'APPROVED', 'ACTIVE', 'DISABLED', 'RETIRED')),
    current_version    INTEGER NOT NULL,
    approved_version   INTEGER,
    active_version     INTEGER,
    author             TEXT NOT NULL,
    source             TEXT NOT NULL CHECK (source IN ('manual', 'ai_draft', 'deterministic_draft')),
    source_incident_id TEXT,
    approved_by        TEXT,
    approved_at        TEXT,
    activated_by       TEXT,
    activated_at       TEXT,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX ix_dsl_rules_status ON dsl_rules(status, updated_at);

CREATE TABLE rule_versions (
    rule_id    TEXT NOT NULL REFERENCES dsl_rules(id),
    version    INTEGER NOT NULL,
    definition TEXT NOT NULL,
    rationale  TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE backtests (
    id           TEXT PRIMARY KEY,
    rule_id      TEXT NOT NULL REFERENCES dsl_rules(id),
    rule_version INTEGER NOT NULL,
    range_start  TEXT NOT NULL,
    range_end    TEXT NOT NULL,
    result       TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX ix_backtests_rule ON backtests(rule_id, rule_version, created_at);
