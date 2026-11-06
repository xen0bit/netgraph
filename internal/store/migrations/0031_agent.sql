-- Optional host-agent inventory. These tables are separate from sensor
-- flows: the agent reports local process identity, not network packets.
CREATE TABLE agents (
    name         TEXT PRIMARY KEY,
    host         TEXT NOT NULL DEFAULT '',
    os           TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    capabilities TEXT NOT NULL DEFAULT '[]',
    boot         TEXT NOT NULL DEFAULT '',
    seq          INTEGER NOT NULL DEFAULT 0,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL
);

CREATE TABLE agent_processes (
    agent      TEXT NOT NULL,
    pid        INTEGER NOT NULL,
    ppid       INTEGER NOT NULL DEFAULT 0,
    uid        INTEGER NOT NULL DEFAULT 0,
    path       TEXT NOT NULL DEFAULT '',
    cmdline    TEXT NOT NULL DEFAULT '',
    code_id    TEXT NOT NULL DEFAULT '',
    sha256     TEXT NOT NULL DEFAULT '',
    signer     TEXT NOT NULL DEFAULT '',
    package    TEXT NOT NULL DEFAULT '',
    start      INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (agent, pid)
);

CREATE TABLE agent_connections (
    agent       TEXT NOT NULL,
    key         TEXT NOT NULL,
    proto       TEXT NOT NULL DEFAULT '',
    local_ip    TEXT NOT NULL DEFAULT '',
    local_port  INTEGER NOT NULL DEFAULT 0,
    remote_ip   TEXT NOT NULL DEFAULT '',
    remote_port INTEGER NOT NULL DEFAULT 0,
    direction   TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT '',
    pid         INTEGER NOT NULL DEFAULT 0,
    uid         INTEGER NOT NULL DEFAULT 0,
    app         TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    code_id     TEXT NOT NULL DEFAULT '',
    sha256      TEXT NOT NULL DEFAULT '',
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    sni         TEXT NOT NULL DEFAULT '',
    http_host   TEXT NOT NULL DEFAULT '',
    predicted   TEXT NOT NULL DEFAULT '',
    scope       TEXT NOT NULL DEFAULT '',
    actual      TEXT NOT NULL DEFAULT '',
    rule        TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    stalled     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent, key)
);

CREATE INDEX agent_processes_last ON agent_processes (agent, last_seen DESC);
CREATE INDEX agent_connections_last ON agent_connections (agent, last_seen DESC);
CREATE INDEX agent_connections_pid ON agent_connections (pid, last_seen DESC);
