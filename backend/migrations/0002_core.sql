-- 0002_core: events, entities, detections, incidents, notes, simulated responses, virtual endpoints, demo runs.
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE events (
    id                  TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    external_id         TEXT,
    digest              TEXT NOT NULL,
    ts                  TEXT NOT NULL,
    kind                TEXT NOT NULL,
    asset               TEXT NOT NULL,
    username            TEXT NOT NULL,
    source_ip           TEXT,
    destination_ip      TEXT,
    destination_port    INTEGER,
    domain              TEXT,
    process_name        TEXT,
    parent_process      TEXT,
    command_line        TEXT,
    file_path           TEXT,
    file_hash           TEXT,
    details             TEXT,
    criticality         INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    privileged          INTEGER NOT NULL CHECK (privileged IN (0, 1)),
    injection_suspected INTEGER NOT NULL DEFAULT 0 CHECK (injection_suspected IN (0, 1)),
    injection_matches   TEXT NOT NULL DEFAULT '[]',
    ingested_at         TEXT NOT NULL,
    ingested_by         TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_events_source_external ON events(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX ix_events_key_ts ON events(asset, username, ts);
CREATE INDEX ix_events_ts ON events(ts);
CREATE INDEX ix_events_kind_ts ON events(kind, ts);

CREATE TABLE raw_events (
    event_id TEXT PRIMARY KEY REFERENCES events(id),
    body     TEXT NOT NULL
);

CREATE TABLE event_entities (
    event_id    TEXT NOT NULL REFERENCES events(id),
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (event_id, entity_type, value)
);
CREATE INDEX ix_event_entities_lookup ON event_entities(entity_type, value);

CREATE TABLE incidents (
    id                TEXT PRIMARY KEY,
    status            TEXT NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'MERGED')),
    revision          INTEGER NOT NULL,
    title             TEXT NOT NULL,
    asset             TEXT NOT NULL,
    username          TEXT NOT NULL,
    owner             TEXT,
    merged_into       TEXT REFERENCES incidents(id),
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    event_count       INTEGER NOT NULL,
    risk_score        INTEGER NOT NULL,
    severity          TEXT NOT NULL,
    risk_factors      TEXT NOT NULL,
    analysis          TEXT NOT NULL,
    closure_category  TEXT,
    closure_entities  TEXT,
    first_detected_at TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    closed_at         TEXT
);
CREATE INDEX ix_incidents_status_updated ON incidents(status, updated_at);
CREATE INDEX ix_incidents_key ON incidents(asset, username);

CREATE TABLE incident_events (
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    event_id    TEXT NOT NULL REFERENCES events(id),
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX ix_incident_events_event ON incident_events(event_id);

-- Detections belong to an incident when one exists; suppressed-only components keep incident_id NULL.
CREATE TABLE detections (
    id             TEXT PRIMARY KEY,
    incident_id    TEXT REFERENCES incidents(id),
    rule_id        TEXT NOT NULL,
    rule_version   INTEGER NOT NULL,
    rule_name      TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     INTEGER NOT NULL,
    stage          TEXT NOT NULL,
    techniques     TEXT NOT NULL,
    group_key      TEXT NOT NULL,
    first_ts       TEXT NOT NULL,
    last_ts        TEXT NOT NULL,
    event_ids      TEXT NOT NULL,
    summary        TEXT NOT NULL,
    details        TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUPPRESSED')),
    suppression_id TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX ix_detections_incident ON detections(incident_id);
CREATE INDEX ix_detections_rule ON detections(rule_id, first_ts);
CREATE INDEX ix_detections_status ON detections(status);

CREATE TABLE detection_events (
    detection_id TEXT NOT NULL REFERENCES detections(id),
    event_id     TEXT NOT NULL REFERENCES events(id),
    PRIMARY KEY (detection_id, event_id)
);
CREATE INDEX ix_detection_events_event ON detection_events(event_id);

CREATE TABLE incident_notes (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    author      TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('note', 'closure', 'reopen', 'ai_reference')),
    text        TEXT NOT NULL,
    ai_job_id   TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX ix_incident_notes_incident ON incident_notes(incident_id, created_at);

CREATE TABLE responses (
    id                TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(id),
    incident_revision INTEGER NOT NULL,
    asset             TEXT NOT NULL,
    playbook          TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'EXECUTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    rationale         TEXT NOT NULL,
    requested_by      TEXT NOT NULL,
    requested_at      TEXT NOT NULL,
    approved_by       TEXT,
    approved_at       TEXT,
    expires_at        TEXT,
    executed_by       TEXT,
    executed_at       TEXT,
    closed_by         TEXT,
    closed_at         TEXT,
    close_reason      TEXT,
    result            TEXT
);
CREATE INDEX ix_responses_incident ON responses(incident_id, status);
CREATE INDEX ix_responses_status ON responses(status, requested_at);

CREATE TABLE virtual_endpoints (
    asset      TEXT PRIMARY KEY,
    state      TEXT NOT NULL CHECK (state IN ('CONNECTED', 'ISOLATED')),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE demo_runs (
    id          TEXT PRIMARY KEY,
    scenario    TEXT NOT NULL,
    mode        TEXT NOT NULL CHECK (mode IN ('instant', 'replay')),
    suffix      TEXT NOT NULL,
    steps       INTEGER NOT NULL,
    released    INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    started_by  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
