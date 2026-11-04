-- Where this database's archive is, so that erasing from the database can always find it, even
-- from a `netgraph db forget` run with no flags, long after the server was set up.
CREATE TABLE archive_location (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    dir        TEXT    NOT NULL,
    raw        INTEGER NOT NULL DEFAULT 0, -- raw connections and lookups are kept too
    updated_at INTEGER NOT NULL
);
