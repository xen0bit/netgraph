-- A decision is the passive analogue of Little Snitch's connection alert.
-- netgraph cannot pause packets at the router; "open" means a connection
-- matched an ask rule (or a silent profile mode) and a person should look.
-- "stalled" is only set by an optional host agent that is really holding it.
CREATE TABLE policy_decisions (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    device      TEXT    NOT NULL DEFAULT '',
    device_name TEXT    NOT NULL DEFAULT '',
    flow_key    TEXT    NOT NULL DEFAULT '',
    direction   TEXT    NOT NULL DEFAULT '',
    remote      TEXT    NOT NULL DEFAULT '',
    port        TEXT    NOT NULL DEFAULT '',
    proto       TEXT    NOT NULL DEFAULT '',
    action      TEXT    NOT NULL DEFAULT 'ask', -- ask, silent-allow, silent-deny
    status      TEXT    NOT NULL DEFAULT 'open', -- open, allowed, denied, rule-created, expired
    rule_id     TEXT    NOT NULL DEFAULT '',
    rule_name   TEXT    NOT NULL DEFAULT '',
    profile     TEXT    NOT NULL DEFAULT '',
    mode        TEXT    NOT NULL DEFAULT '',
    stalled     INTEGER NOT NULL DEFAULT 0,
    unconfirmed INTEGER NOT NULL DEFAULT 1,
    decided_at  INTEGER NOT NULL DEFAULT 0,
    decided_by  TEXT    NOT NULL DEFAULT '',
    note        TEXT    NOT NULL DEFAULT '',
    created     INTEGER NOT NULL,
    modified    INTEGER NOT NULL
);

CREATE INDEX policy_decisions_status ON policy_decisions (status, ts DESC);
CREATE INDEX policy_decisions_flow ON policy_decisions (flow_key, status);
CREATE INDEX policy_decisions_device ON policy_decisions (device, ts DESC);
