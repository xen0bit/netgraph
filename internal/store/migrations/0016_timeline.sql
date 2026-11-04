-- The Flight Recorder's event index. It is derived, append-only data: it
-- points at the authoritative rows (observations, dns, connections) and can
-- be dropped and rebuilt. The unique key makes a retried batch idempotent.
CREATE TABLE timeline_events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    entity_id   INTEGER NOT NULL DEFAULT 0,
    entity_key  TEXT    NOT NULL DEFAULT '',
    related_id  INTEGER NOT NULL DEFAULT 0,
    related_key TEXT    NOT NULL DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT '',
    title       TEXT    NOT NULL,
    ref_table   TEXT    NOT NULL DEFAULT '',
    ref_key     TEXT    NOT NULL DEFAULT '',
    attrs       TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX timeline_events_time ON timeline_events (ts, id);
CREATE INDEX timeline_events_entity ON timeline_events (entity_id, ts);
CREATE INDEX timeline_events_kind ON timeline_events (kind, ts);
CREATE UNIQUE INDEX timeline_events_ref ON timeline_events (kind, ref_table, ref_key, entity_id);
