-- Human memory: notes and bookmarks on the timeline. These are not derived
-- data; they are kept until explicitly deleted.
CREATE TABLE annotations (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    entity  TEXT    NOT NULL DEFAULT '',
    kind    TEXT    NOT NULL DEFAULT '',
    text    TEXT    NOT NULL,
    author  TEXT    NOT NULL DEFAULT '',
    created INTEGER NOT NULL
);
CREATE INDEX annotations_time ON annotations (ts, id);
CREATE INDEX annotations_entity ON annotations (entity, ts);

CREATE TABLE bookmarks (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    entity  TEXT    NOT NULL DEFAULT '',
    name    TEXT    NOT NULL,
    created INTEGER NOT NULL
);
CREATE INDEX bookmarks_time ON bookmarks (ts, id);
