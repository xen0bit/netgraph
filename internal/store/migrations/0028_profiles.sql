-- Profiles group rules for a network context ("home", "cafe", "lab").
-- Network triggers activate a profile when the observed network signature
-- matches. A signature is a stable string built from the fields netgraph can
-- see; missing fields are omitted, and a trigger may use * or ? globs.
CREATE TABLE profiles (
    id          INTEGER PRIMARY KEY,
    auid        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 0,
    mode        TEXT    NOT NULL DEFAULT 'alert', -- alert, silent-allow, silent-deny
    dns_exceptions TEXT NOT NULL DEFAULT '[]',
    is_default  INTEGER NOT NULL DEFAULT 0,
    created     INTEGER NOT NULL,
    modified    INTEGER NOT NULL
);

CREATE UNIQUE INDEX profiles_one_active ON profiles (active) WHERE active = 1;
CREATE UNIQUE INDEX profiles_one_default ON profiles (is_default) WHERE is_default = 1;

CREATE TABLE network_triggers (
    id          INTEGER PRIMARY KEY,
    auid        TEXT    NOT NULL UNIQUE,
    profile_id  INTEGER NOT NULL,
    signature   TEXT    NOT NULL,
    action      TEXT    NOT NULL DEFAULT 'activate', -- activate, deactivate, ask, none
    mode        TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_triggered INTEGER NOT NULL DEFAULT 0,
    created     INTEGER NOT NULL,
    modified    INTEGER NOT NULL
);

CREATE INDEX network_triggers_enabled ON network_triggers (enabled, id);
CREATE INDEX network_triggers_profile ON network_triggers (profile_id);
