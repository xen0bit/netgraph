-- What's wanted of each sensor ('*' for all of them), and the counters before the latest,
-- to tell what's going wrong now from what went wrong days ago.
CREATE TABLE sensor_config (
    name       TEXT    PRIMARY KEY,
    settings   TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
ALTER TABLE sensors ADD COLUMN stats_prev TEXT NOT NULL DEFAULT '{}';
