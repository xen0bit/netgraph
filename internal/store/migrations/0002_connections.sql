-- One row per connection with its totals, kept current by ingest. A
-- window query reads these; only connections crossing a window edge go
-- back to their interval records in flows to prorate.
CREATE TABLE connections (
    flow_key      TEXT    PRIMARY KEY,
    sensor_id     INTEGER NOT NULL,
    proto         INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    client_port   INTEGER NOT NULL,
    client_mac    TEXT    NOT NULL DEFAULT '',
    client_device INTEGER NOT NULL DEFAULT 0,
    remote_ip     TEXT    NOT NULL,
    remote_port   INTEGER NOT NULL,
    direction     TEXT    NOT NULL,
    multicast     INTEGER NOT NULL DEFAULT 0,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL, -- latest record end
    final         INTEGER NOT NULL DEFAULT 0,
    end_reason    TEXT    NOT NULL DEFAULT '',
    app           TEXT    NOT NULL DEFAULT '',
    sni           TEXT    NOT NULL DEFAULT '',
    alpn          TEXT    NOT NULL DEFAULT '',
    ja4           TEXT    NOT NULL DEFAULT '',
    http_host     TEXT    NOT NULL DEFAULT '',
    user_agent    TEXT    NOT NULL DEFAULT '',
    qname         TEXT    NOT NULL DEFAULT '',
    bytes_out     INTEGER NOT NULL DEFAULT 0,
    bytes_in      INTEGER NOT NULL DEFAULT 0,
    pkts_out      INTEGER NOT NULL DEFAULT 0,
    pkts_in       INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX connections_time ON connections (last_seen, first_seen);
CREATE INDEX connections_device ON connections (client_device, last_seen);

INSERT INTO connections
SELECT flow_key, max(sensor_id), max(proto), max(client_ip), max(client_port), max(client_mac), max(client_device),
       max(remote_ip), max(remote_port), max(direction), max(multicast), min(first_seen), max(t_end), max(final),
       max(CASE WHEN final = 1 THEN end_reason ELSE '' END), max(app), max(sni), max(alpn), max(ja4), max(http_host),
       max(user_agent), max(qname), sum(bytes_out), sum(bytes_in), sum(pkts_out), sum(pkts_in)
FROM flows GROUP BY flow_key;
