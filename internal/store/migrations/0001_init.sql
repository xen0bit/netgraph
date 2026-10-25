-- netgraph schema v1. Times are unix milliseconds.

-- Sensors that have sent data, with their latest hello and stats.
CREATE TABLE sensors (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    version    TEXT    NOT NULL DEFAULT '',
    hello      TEXT    NOT NULL DEFAULT '{}',
    stats      TEXT    NOT NULL DEFAULT '{}'
);

-- The last sequence number ingested per sensor boot: retried batches are
-- dropped instead of counted twice.
CREATE TABLE ingest_seq (
    sensor_id INTEGER NOT NULL,
    boot      TEXT    NOT NULL,
    last_seq  INTEGER NOT NULL,
    updated   INTEGER NOT NULL,
    PRIMARY KEY (sensor_id, boot)
) WITHOUT ROWID;

-- Everything the graph has a node for: devices (by MAC), addresses, DNS
-- names, hostnames, vendors, services, fingerprints, user agents, ...
CREATE TABLE entities (
    id         INTEGER PRIMARY KEY,
    kind       TEXT    NOT NULL,
    key        TEXT    NOT NULL,
    label      TEXT    NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    attrs      TEXT    NOT NULL DEFAULT '{}',
    UNIQUE (kind, key)
);
CREATE INDEX entities_kind_seen ON entities (kind, last_seen);

-- Relationships that hold over an interval. Re-observing one within the
-- ingester's gap extends its row; a longer silence starts a new row, so the
-- rows of (rel, src, dst) are the periods it held.
CREATE TABLE facts (
    id         INTEGER PRIMARY KEY,
    rel        TEXT    NOT NULL,
    src        INTEGER NOT NULL REFERENCES entities (id),
    dst        INTEGER NOT NULL REFERENCES entities (id),
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    source     TEXT    NOT NULL DEFAULT '',
    attrs      TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX facts_key ON facts (rel, src, dst, last_seen);
CREATE INDEX facts_time ON facts (last_seen, first_seen);
CREATE INDEX facts_src ON facts (src, last_seen);
CREATE INDEX facts_dst ON facts (dst, last_seen);

-- Flow interval records as the sensor sent them, plus what ingest worked
-- out: which side is the local client, its device, and the DNS name the
-- remote address was resolved from.
CREATE TABLE flows (
    id            INTEGER PRIMARY KEY,
    sensor_id     INTEGER NOT NULL,
    flow_key      TEXT    NOT NULL, -- "<sensor>:<boot>:<id>"
    proto         INTEGER NOT NULL,
    src_ip        TEXT    NOT NULL,
    src_port      INTEGER NOT NULL,
    dst_ip        TEXT    NOT NULL,
    dst_port      INTEGER NOT NULL,
    first_seen    INTEGER NOT NULL,
    t_start       INTEGER NOT NULL,
    t_end         INTEGER NOT NULL,
    bytes_out     INTEGER NOT NULL,
    bytes_in      INTEGER NOT NULL,
    pkts_out      INTEGER NOT NULL,
    pkts_in       INTEGER NOT NULL,
    tcp_flags     INTEGER NOT NULL DEFAULT 0,
    final         INTEGER NOT NULL DEFAULT 0,
    end_reason    TEXT    NOT NULL DEFAULT '',
    app           TEXT    NOT NULL DEFAULT '',
    sni           TEXT    NOT NULL DEFAULT '',
    alpn          TEXT    NOT NULL DEFAULT '',
    ja4           TEXT    NOT NULL DEFAULT '',
    http_host     TEXT    NOT NULL DEFAULT '',
    user_agent    TEXT    NOT NULL DEFAULT '',
    qname         TEXT    NOT NULL DEFAULT '',
    client_ip     TEXT    NOT NULL,
    client_port   INTEGER NOT NULL,
    client_mac    TEXT    NOT NULL DEFAULT '',
    client_device INTEGER NOT NULL DEFAULT 0,
    remote_ip     TEXT    NOT NULL,
    remote_port   INTEGER NOT NULL,
    direction     TEXT    NOT NULL, -- out, in, local, external
    multicast     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX flows_time ON flows (t_end, t_start);
CREATE INDEX flows_key ON flows (flow_key);
CREATE INDEX flows_device ON flows (client_device, t_end);
CREATE INDEX flows_remote ON flows (remote_ip, t_end);

-- DNS lookups and their answers.
CREATE TABLE dns (
    id            INTEGER PRIMARY KEY,
    sensor_id     INTEGER NOT NULL,
    ts            INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    client_device INTEGER NOT NULL DEFAULT 0,
    server_ip     TEXT    NOT NULL,
    proto         TEXT    NOT NULL,
    qname         TEXT    NOT NULL,
    qtype         TEXT    NOT NULL,
    rcode         TEXT    NOT NULL,
    latency_ms    REAL,
    answers       TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX dns_time ON dns (ts);
CREATE INDEX dns_qname ON dns (qname, ts);
CREATE INDEX dns_device ON dns (client_device, ts);

-- Answers flattened for correlation: which name an address came from, for
-- whom, and until when the answer was valid.
CREATE TABLE dns_answers (
    dns_id    INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    expires   INTEGER NOT NULL,
    client_ip TEXT    NOT NULL,
    qname     TEXT    NOT NULL,
    name      TEXT    NOT NULL,
    type      TEXT    NOT NULL,
    data      TEXT    NOT NULL,
    ttl       INTEGER NOT NULL
);
CREATE INDEX dns_answers_data ON dns_answers (data, expires);
CREATE INDEX dns_answers_time ON dns_answers (expires, ts);
CREATE INDEX dns_answers_dns ON dns_answers (dns_id);

-- Identity observations (DHCP, mDNS, SSDP, NBNS/LLMNR, LLDP, bindings) as
-- received, for entity timelines and re-processing.
CREATE TABLE observations (
    id        INTEGER PRIMARY KEY,
    sensor_id INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    type      TEXT    NOT NULL,
    device    INTEGER NOT NULL DEFAULT 0,
    ip        TEXT    NOT NULL DEFAULT '',
    data      TEXT    NOT NULL
);
CREATE INDEX observations_time ON observations (ts);
CREATE INDEX observations_device ON observations (device, ts);

-- Hourly rollups that outlive the raw tables, for windows older than raw
-- retention. name is the flow's best name (SNI, HTTP host or DNS name).
CREATE TABLE traffic_hourly (
    bucket        INTEGER NOT NULL,
    client_device INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    remote_ip     TEXT    NOT NULL,
    remote_port   INTEGER NOT NULL,
    proto         INTEGER NOT NULL,
    name          TEXT    NOT NULL,
    app           TEXT    NOT NULL,
    multicast     INTEGER NOT NULL,
    flows         INTEGER NOT NULL,
    bytes_out     INTEGER NOT NULL,
    bytes_in      INTEGER NOT NULL,
    PRIMARY KEY (bucket, client_device, client_ip, remote_ip, remote_port, proto, name)
) WITHOUT ROWID;

CREATE TABLE dns_hourly (
    bucket        INTEGER NOT NULL,
    client_device INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    qname         TEXT    NOT NULL,
    qtype         TEXT    NOT NULL,
    rcode         TEXT    NOT NULL,
    count         INTEGER NOT NULL,
    PRIMARY KEY (bucket, client_device, client_ip, qname, qtype, rcode)
) WITHOUT ROWID;
