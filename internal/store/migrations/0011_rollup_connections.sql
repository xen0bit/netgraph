-- Hourly rollups must keep one row per connection per hour, not one row per
-- destination: a connection that stays open across hours has to count once
-- (distinct flow_key), while its bytes still spread over the hours it was
-- active. The old primary key also folded a connection into two rows when
-- its SNI or HTTP Host was learned after the first interval.
--
-- Legacy rows cannot be split back into their connections, so each becomes a
-- synthetic flow_key; their existing `flows` count remains the best estimate.
CREATE TABLE traffic_hourly_new (
    bucket        INTEGER NOT NULL,
    flow_key      TEXT    NOT NULL,
    client_device INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    remote_ip     TEXT    NOT NULL,
    remote_port   INTEGER NOT NULL, -- the server's port: the device's own for direction 'in'
    proto         INTEGER NOT NULL,
    name          TEXT    NOT NULL,
    direction     TEXT    NOT NULL DEFAULT 'out',
    app           TEXT    NOT NULL,
    multicast     INTEGER NOT NULL,
    flows         INTEGER NOT NULL, -- connections opened in this bucket
    bytes_out     INTEGER NOT NULL,
    bytes_in      INTEGER NOT NULL,
    remote_asn    INTEGER,
    remote_cc     TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (bucket, flow_key)
) WITHOUT ROWID;

INSERT INTO traffic_hourly_new (bucket, flow_key, client_device, client_ip, remote_ip, remote_port, proto, name, direction, app, multicast, flows, bytes_out, bytes_in, remote_asn, remote_cc)
SELECT bucket,
    'legacy:' || bucket || ':' || client_device || ':' || client_ip || ':' || remote_ip || ':' ||
        remote_port || ':' || proto || ':' || name || ':' || direction,
    client_device, client_ip, remote_ip, remote_port, proto, name, direction, app, multicast,
    flows, bytes_out, bytes_in, remote_asn, remote_cc
FROM traffic_hourly;

DROP TABLE traffic_hourly;
ALTER TABLE traffic_hourly_new RENAME TO traffic_hourly;

CREATE INDEX traffic_hourly_asn ON traffic_hourly (remote_asn, bucket);
CREATE INDEX traffic_hourly_device ON traffic_hourly (client_device, bucket);
