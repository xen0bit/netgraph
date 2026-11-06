-- Blocklists and rule groups. A group is a collection of entries a person can
-- enable as a unit; a blocklist is one source inside it. Entries are stored
-- parsed, never as the fetched payload, so a bad feed can be removed without
-- losing the rest of the group.
CREATE TABLE rule_groups (
    id              INTEGER PRIMARY KEY,
    auid            TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    type            TEXT    NOT NULL DEFAULT 'local', -- factory, remote, local
    url             TEXT    NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    update_interval INTEGER NOT NULL DEFAULT 86400,
    last_success    INTEGER NOT NULL DEFAULT 0,
    last_failure    INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    etag            TEXT    NOT NULL DEFAULT '',
    last_modified   TEXT    NOT NULL DEFAULT '',
    invalid_entries INTEGER NOT NULL DEFAULT 0,
    created         INTEGER NOT NULL,
    modified        INTEGER NOT NULL
);

CREATE TABLE blocklists (
    id              INTEGER PRIMARY KEY,
    auid            TEXT    NOT NULL UNIQUE,
    group_id        INTEGER,
    name            TEXT    NOT NULL,
    url             TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'auto',
    enabled         INTEGER NOT NULL DEFAULT 1,
    update_interval INTEGER NOT NULL DEFAULT 86400,
    last_success    INTEGER NOT NULL DEFAULT 0,
    last_failure    INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    etag            TEXT    NOT NULL DEFAULT '',
    last_modified   TEXT    NOT NULL DEFAULT '',
    entry_count     INTEGER NOT NULL DEFAULT 0,
    invalid_entries INTEGER NOT NULL DEFAULT 0,
    created         INTEGER NOT NULL,
    modified        INTEGER NOT NULL
);

CREATE INDEX blocklists_group ON blocklists (group_id);
CREATE INDEX blocklists_updated ON blocklists (last_success);

CREATE TABLE blocklist_entries (
    id           INTEGER PRIMARY KEY,
    blocklist_id INTEGER NOT NULL,
    kind         TEXT    NOT NULL, -- domain, host, ip
    value        TEXT    NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    unapproved   INTEGER NOT NULL DEFAULT 0,
    use_count    INTEGER NOT NULL DEFAULT 0,
    last_used    INTEGER NOT NULL DEFAULT 0,
    notes        TEXT    NOT NULL DEFAULT '',
    UNIQUE (blocklist_id, kind, value)
);

CREATE INDEX blocklist_entries_list ON blocklist_entries (blocklist_id, kind, value);
CREATE INDEX blocklist_entries_used ON blocklist_entries (last_used);
