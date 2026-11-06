-- Durable policy objects. Version 1 policies remain first-match; version 2
-- policies use the documented precedence order. The canonical JSON body is
-- kept alongside normalized rules so a policy round-trips exactly while the
-- rules stay queryable for audit and the blocklist index.
CREATE TABLE policies (
    id       INTEGER PRIMARY KEY,
    auid     TEXT    NOT NULL UNIQUE,
    name     TEXT    NOT NULL,
    version  INTEGER NOT NULL,
    mode     TEXT    NOT NULL DEFAULT 'precedence',
    active   INTEGER NOT NULL DEFAULT 0,
    notes    TEXT    NOT NULL DEFAULT '',
    body     TEXT    NOT NULL DEFAULT '',
    created  INTEGER NOT NULL,
    modified INTEGER NOT NULL
);

-- At most one active policy. A partial index is portable in modernc SQLite.
CREATE UNIQUE INDEX policies_one_active ON policies (active) WHERE active = 1;
CREATE INDEX policies_modified ON policies (modified DESC);

CREATE TABLE policy_rules (
    id              INTEGER PRIMARY KEY,
    auid            TEXT    NOT NULL UNIQUE,
    policy_id       INTEGER NOT NULL,
    name            TEXT    NOT NULL,
    notes           TEXT    NOT NULL DEFAULT '',
    origin          TEXT    NOT NULL DEFAULT 'user',
    action          TEXT    NOT NULL,
    direction       TEXT    NOT NULL DEFAULT 'both',
    priority        TEXT    NOT NULL DEFAULT 'regular',
    enabled         INTEGER NOT NULL DEFAULT 1,
    protected       INTEGER NOT NULL DEFAULT 0,
    profile         TEXT    NOT NULL DEFAULT '',
    group_name      TEXT    NOT NULL DEFAULT '',
    local_selector  TEXT    NOT NULL DEFAULT '{"type":"any"}',
    remote_type     TEXT    NOT NULL DEFAULT 'any',
    remote_values   TEXT    NOT NULL DEFAULT '[]',
    ports           TEXT    NOT NULL DEFAULT '[]',
    protocol        TEXT    NOT NULL DEFAULT 'any',
    lifetime        TEXT    NOT NULL DEFAULT 'permanent',
    expiry          INTEGER NOT NULL DEFAULT 0,
    code_requirement TEXT   NOT NULL DEFAULT '',
    requires_trusted INTEGER NOT NULL DEFAULT 0,
    created         INTEGER NOT NULL,
    modified        INTEGER NOT NULL,
    last_used       INTEGER NOT NULL DEFAULT 0,
    use_count       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX policy_rules_policy ON policy_rules (policy_id, priority, id);
CREATE INDEX policy_rules_remote ON policy_rules (remote_type);
CREATE INDEX policy_rules_profile ON policy_rules (profile) WHERE profile != '';

-- The agent path (item 11) will fill these; passive captures leave them empty.
ALTER TABLE flows ADD COLUMN client_app_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE flows ADD COLUMN client_process TEXT NOT NULL DEFAULT '';
ALTER TABLE flows ADD COLUMN client_uid INTEGER;
ALTER TABLE connections ADD COLUMN client_app_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN client_process TEXT NOT NULL DEFAULT '';
ALTER TABLE connections ADD COLUMN client_uid INTEGER;
