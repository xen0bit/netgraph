-- The built-in DNS server (netgraph serve -dns-listen): rules a person wrote
-- to block or allow names, for everyone, one device (by MAC) or a group, and
-- which rule or list blocked each lookup it refused.
CREATE TABLE dns_rules (
    id          INTEGER PRIMARY KEY,
    auid        TEXT    NOT NULL UNIQUE,
    scope       TEXT    NOT NULL DEFAULT 'all', -- all, device, group
    scope_value TEXT    NOT NULL DEFAULT '',    -- the device's MAC or the group's name
    action      TEXT    NOT NULL,               -- block, allow
    pattern     TEXT    NOT NULL,               -- a name (and its subdomains), or * for every name
    note        TEXT    NOT NULL DEFAULT '',
    created     INTEGER NOT NULL,
    modified    INTEGER NOT NULL,
    UNIQUE (scope, scope_value, pattern)
);
CREATE INDEX dns_rules_scope ON dns_rules (scope, scope_value);

ALTER TABLE dns ADD COLUMN blocked_by TEXT NOT NULL DEFAULT '';
