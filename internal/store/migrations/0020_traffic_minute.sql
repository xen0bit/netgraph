-- Per-minute traffic: enough for a scrubbable timeline over weeks, far smaller
-- than interval records. It aggregates by service, not by connection, so it
-- can say how much moved but not how many connections were open.
CREATE TABLE traffic_minute (
    bucket        INTEGER NOT NULL,
    client_device INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    remote_ip     TEXT    NOT NULL,
    remote_port   INTEGER NOT NULL, -- the server's port: the device's own for direction 'in'
    proto         INTEGER NOT NULL,
    name          TEXT    NOT NULL,
    direction     TEXT    NOT NULL,
    app           TEXT    NOT NULL,
    multicast     INTEGER NOT NULL,
    flows         INTEGER NOT NULL, -- connections opened in this minute
    bytes_out     INTEGER NOT NULL,
    bytes_in      INTEGER NOT NULL,
    remote_asn    INTEGER,
    remote_cc     TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (bucket, client_device, client_ip, remote_ip, remote_port, proto, name, direction, app)
) WITHOUT ROWID;

-- What is already recorded becomes minutes too. A record's bytes go to the
-- minute it ended in: records are short, and this runs once.
INSERT INTO traffic_minute (bucket, client_device, client_ip, remote_ip, remote_port, proto, name, direction, app, multicast, flows, bytes_out, bytes_in, remote_asn, remote_cc)
SELECT f.t_end - f.t_end % 60000, f.client_device, f.client_ip, f.remote_ip,
       CASE WHEN f.direction = 'in' THEN f.client_port ELSE f.remote_port END,
       f.proto, coalesce(nullif(f.sni, ''), nullif(f.http_host, ''), f.qname), f.direction, f.app, f.multicast,
       sum(f.t_start = f.first_seen), sum(f.bytes_out), sum(f.bytes_in), max(c.remote_asn), coalesce(max(c.remote_cc), '')
FROM flows f LEFT JOIN connections c ON c.flow_key = f.flow_key
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9;
