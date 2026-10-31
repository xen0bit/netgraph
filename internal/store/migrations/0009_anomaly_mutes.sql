CREATE TABLE anomaly_mutes (
    kind    TEXT NOT NULL DEFAULT '',
    device  TEXT NOT NULL DEFAULT '',
    entity  TEXT NOT NULL DEFAULT '',
    until   INTEGER NOT NULL,
    note    TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL,
    PRIMARY KEY (kind, device, entity)
);
CREATE INDEX anomaly_mutes_until ON anomaly_mutes (until);
