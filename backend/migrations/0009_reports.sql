-- 0009_reports: organisation profile and CERT-In report drafts with versions (I1).
-- Append-only: never edit this file after it has been applied; add a new migration instead.

CREATE TABLE org_profile (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    organization_name TEXT NOT NULL,
    sector            TEXT NOT NULL,
    contact_name      TEXT NOT NULL,
    contact_email     TEXT NOT NULL,
    contact_phone     TEXT NOT NULL,
    address           TEXT,
    updated_by        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE cert_in_reports (
    id                   TEXT PRIMARY KEY,
    incident_id          TEXT NOT NULL REFERENCES incidents(id),
    incident_revision    INTEGER NOT NULL,
    status               TEXT NOT NULL CHECK (status IN ('DRAFT', 'IN_REVIEW', 'APPROVED', 'MARKED_SUBMITTED')),
    current_version      INTEGER NOT NULL,
    detected_at          TEXT NOT NULL,
    deadline_at          TEXT NOT NULL,
    template_version     TEXT NOT NULL,
    created_by           TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    reviewed_by          TEXT,
    reviewed_at          TEXT,
    approved_by          TEXT,
    approved_at          TEXT,
    submitted_by         TEXT,
    submitted_at         TEXT,
    submission_reference TEXT,
    submission_note      TEXT,
    UNIQUE (incident_id)
);
CREATE INDEX ix_cert_in_reports_status ON cert_in_reports(status, deadline_at);

CREATE TABLE report_versions (
    report_id     TEXT NOT NULL REFERENCES cert_in_reports(id),
    version       INTEGER NOT NULL,
    fields        TEXT NOT NULL,
    reportability TEXT NOT NULL,
    ai_status     TEXT,
    provider      TEXT,
    model         TEXT,
    note          TEXT,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (report_id, version)
);
