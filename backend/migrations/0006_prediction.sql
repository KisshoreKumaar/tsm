-- 0006_prediction: next-step predictions with watchlist state (F4) and explanations of top predictions.
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE predictions (
    id                 TEXT PRIMARY KEY,
    incident_id        TEXT NOT NULL REFERENCES incidents(id),
    technique_id       TEXT NOT NULL,
    technique_name     TEXT NOT NULL,
    tactic             TEXT NOT NULL,
    label              TEXT NOT NULL DEFAULT 'HYPOTHESIS' CHECK (label = 'HYPOTHESIS'),
    score              INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    band               TEXT NOT NULL CHECK (band IN ('LOW', 'MEDIUM', 'HIGH')),
    factors            TEXT NOT NULL,
    rationale          TEXT NOT NULL,
    sources            TEXT NOT NULL,
    evidence_ids       TEXT NOT NULL,
    watch_signals      TEXT NOT NULL,
    preventive_actions TEXT NOT NULL,
    horizon_seconds    INTEGER NOT NULL,
    predicted_at       TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('WATCHING', 'OBSERVED', 'EXPIRED')),
    observed_event_ids TEXT NOT NULL DEFAULT '[]',
    observed_at        TEXT,
    status_changed_at  TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE (incident_id, technique_id)
);
CREATE INDEX ix_predictions_status ON predictions(status, expires_at);

CREATE TABLE prediction_explanations (
    id                TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(id),
    incident_revision INTEGER NOT NULL,
    content           TEXT NOT NULL,
    ai_status         TEXT NOT NULL,
    provider          TEXT,
    model             TEXT,
    job_id            TEXT,
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
CREATE INDEX ix_prediction_explanations_incident ON prediction_explanations(incident_id, created_at);
