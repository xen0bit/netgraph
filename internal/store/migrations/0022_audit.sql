-- Who changed what, through the API. Kept with the rollups, and erased like the rest:
-- a target can name a device.
CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    actor  TEXT    NOT NULL, -- a person's name from a trusted proxy, or how they got in
    role   TEXT    NOT NULL,
    action TEXT    NOT NULL, -- the route: "PUT /api/v1/devices/{mac}/label"
    target TEXT    NOT NULL DEFAULT '',
    remote TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_ts ON audit_log (ts);
