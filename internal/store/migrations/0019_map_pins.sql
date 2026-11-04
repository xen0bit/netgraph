-- Where a person put a node on the map. A preference, not derived data: kept
-- until unpinned, or erased with what it names by db forget and db purge.
CREATE TABLE map_pins (
    id      TEXT PRIMARY KEY,
    x       REAL NOT NULL,
    y       REAL NOT NULL,
    updated INTEGER NOT NULL
) WITHOUT ROWID;
