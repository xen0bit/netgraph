-- Findings that remember: an anomaly the checks keep producing is one row with a
-- lifecycle, so it can be read, acknowledged and resolved, and its return noticed.
CREATE TABLE findings (
    id           INTEGER PRIMARY KEY,
    key          TEXT    NOT NULL UNIQUE, -- kind, device and entity: what makes it the same finding
    kind         TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    device       TEXT    NOT NULL DEFAULT '',
    device_name  TEXT    NOT NULL DEFAULT '',
    entity       TEXT    NOT NULL DEFAULT '',
    summary      TEXT    NOT NULL,
    evidence     TEXT    NOT NULL DEFAULT '{}',
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    occurrences  INTEGER NOT NULL DEFAULT 1,
    status       TEXT    NOT NULL DEFAULT 'new', -- new, seen, acknowledged, resolved, dismissed
    status_at    INTEGER NOT NULL,
    auto_resolved INTEGER NOT NULL DEFAULT 0,
    recurrences  INTEGER NOT NULL DEFAULT 0,
    note         TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX findings_status ON findings (status, last_seen);
CREATE INDEX findings_device ON findings (device, kind);
CREATE INDEX findings_last ON findings (last_seen);
