-- VPN sessions an edge reported: who held which inner prefixes, and when.
-- A session's identity is what its protocol's handshake proved, so a flow
-- from one of its prefixes while it was open is attributed to that user
-- (flows.vpn_session) by evidence, not inference.
CREATE TABLE vpn_sessions (
    id         INTEGER PRIMARY KEY,
    sensor_id  INTEGER NOT NULL,          -- the edge
    boot       TEXT    NOT NULL,
    listener   TEXT    NOT NULL,
    session    INTEGER NOT NULL,          -- the edge's ID, unique per listener and boot
    protocol   TEXT    NOT NULL,
    user       TEXT    NOT NULL,
    auth       TEXT    NOT NULL DEFAULT '', -- how user was proved: public-key, certificate, eap-mschapv2, password, psk
    name       TEXT    NOT NULL DEFAULT '',
    prefixes   TEXT    NOT NULL DEFAULT '[]', -- JSON array of inner prefixes
    outer      TEXT    NOT NULL DEFAULT '',
    t_start    INTEGER NOT NULL,
    t_end      INTEGER,                   -- NULL while open
    reason     TEXT    NOT NULL DEFAULT '',
    UNIQUE (sensor_id, boot, listener, session)
);
CREATE INDEX vpn_sessions_time ON vpn_sessions (sensor_id, t_start);
CREATE INDEX vpn_sessions_end ON vpn_sessions (t_end);
CREATE INDEX vpn_sessions_user ON vpn_sessions (user, t_start);

ALTER TABLE flows ADD COLUMN vpn_session INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN vpn_session INTEGER NOT NULL DEFAULT 0;
