-- Saved investigations. Anomalies are ephemeral; an incident pins the
-- evidence and window a person wants to keep.
CREATE TABLE incidents (
    id          INTEGER PRIMARY KEY,
    opened      INTEGER NOT NULL,
    updated     INTEGER NOT NULL,
    start_ts    INTEGER NOT NULL,
    end_ts      INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open',
    title       TEXT    NOT NULL,
    summary     TEXT    NOT NULL DEFAULT '',
    anomaly     TEXT    NOT NULL DEFAULT '{}',
    created_by  TEXT    NOT NULL DEFAULT '',
    attrs       TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX incidents_time ON incidents (start_ts, end_ts);
CREATE INDEX incidents_status ON incidents (status, updated);

CREATE TABLE incident_entities (
    incident_id INTEGER NOT NULL,
    entity      TEXT    NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'subject',
    PRIMARY KEY (incident_id, entity)
) WITHOUT ROWID;

CREATE TABLE incident_notes (
    id          INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    author      TEXT    NOT NULL DEFAULT '',
    body        TEXT    NOT NULL
);
CREATE INDEX incident_notes_time ON incident_notes (incident_id, ts);

CREATE TABLE incident_evidence (
    incident_id INTEGER NOT NULL,
    evidence    TEXT    NOT NULL,
    pinned      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (incident_id, evidence)
) WITHOUT ROWID;
