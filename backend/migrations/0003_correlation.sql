-- 0003_correlation: campaigns (F1) and explained correlation links between incidents.
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE campaigns (
    id             TEXT PRIMARY KEY,
    status         TEXT NOT NULL CHECK (status IN ('ACTIVE', 'MERGED', 'DISSOLVED')),
    merged_into    TEXT REFERENCES campaigns(id),
    revision       INTEGER NOT NULL,
    title          TEXT NOT NULL,
    risk_score     INTEGER NOT NULL,
    severity       TEXT NOT NULL,
    risk_factors   TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    incident_count INTEGER NOT NULL,
    assets         TEXT NOT NULL,
    users          TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX ix_campaigns_status ON campaigns(status, updated_at);

CREATE TABLE campaign_incidents (
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    PRIMARY KEY (campaign_id, incident_id)
);
CREATE INDEX ix_campaign_incidents_incident ON campaign_incidents(incident_id);

CREATE TABLE correlation_links (
    id                   TEXT PRIMARY KEY,
    incident_a           TEXT NOT NULL REFERENCES incidents(id),
    incident_b           TEXT NOT NULL REFERENCES incidents(id),
    link_type            TEXT NOT NULL,
    entity_type          TEXT NOT NULL,
    entity_value         TEXT NOT NULL,
    time_delta_seconds   INTEGER NOT NULL,
    strength             REAL NOT NULL,
    supporting_event_ids TEXT NOT NULL,
    campaign_id          TEXT REFERENCES campaigns(id),
    created_at           TEXT NOT NULL
);
CREATE INDEX ix_correlation_links_a ON correlation_links(incident_a);
CREATE INDEX ix_correlation_links_b ON correlation_links(incident_b);
CREATE INDEX ix_correlation_links_campaign ON correlation_links(campaign_id);
