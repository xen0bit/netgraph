-- Inbound connections: someone outside opened a connection to a device here
-- (a server, a published port). Their rows always kept the device as the
-- "client" side, but counted bytes from the initiator's side and credited
-- the initiator's TLS fingerprint and user agent to the device, and the SNI
-- it asked for to its own address ("ip serves domain"). Count from the
-- device's side, as for every other connection, and drop what was credited
-- to the wrong end.

UPDATE flows SET bytes_out = bytes_in, bytes_in = bytes_out, pkts_out = pkts_in, pkts_in = pkts_out, qname = ''
WHERE direction = 'in';
UPDATE connections SET bytes_out = bytes_in, bytes_in = bytes_out, pkts_out = pkts_in, pkts_in = pkts_out, qname = ''
WHERE direction = 'in';

-- "serves" facts from an inbound connection's initiator, unless some other
-- connection to that address named the same server.
CREATE TEMP TABLE inbound_names AS
SELECT DISTINCT remote_ip AS ip, sni AS name FROM connections WHERE direction = 'in' AND sni != ''
UNION SELECT remote_ip, http_host FROM connections WHERE direction = 'in' AND http_host != '';
DELETE FROM inbound_names WHERE (ip, name) IN (
    SELECT remote_ip, sni FROM connections WHERE direction != 'in' AND sni != ''
    UNION SELECT remote_ip, http_host FROM connections WHERE direction != 'in' AND http_host != '');
DELETE FROM facts WHERE id IN (
    SELECT f.id FROM inbound_names x
    JOIN entities ip ON ip.kind = 'ip' AND ip.key = x.ip
    JOIN entities d ON d.kind = 'domain' AND d.key = x.name
    JOIN facts f ON f.rel = 'serves' AND f.src = ip.id AND f.dst = d.id);
DROP TABLE temp.inbound_names;

-- Fingerprints and user agents a device only ever "sent" on inbound
-- connections were its visitors'.
CREATE TEMP TABLE inbound_ids AS
SELECT DISTINCT client_device AS dev, 'fingerprint' AS rel, 'fingerprint' AS kind, 'ja4:' || ja4 AS key
FROM connections WHERE direction = 'in' AND ja4 != '' AND client_device != 0
UNION SELECT client_device, 'user_agent', 'useragent', user_agent
FROM connections WHERE direction = 'in' AND user_agent != '' AND client_device != 0;
DELETE FROM inbound_ids WHERE (dev, rel, key) IN (
    SELECT client_device, 'fingerprint', 'ja4:' || ja4 FROM connections WHERE direction != 'in' AND ja4 != ''
    UNION SELECT client_device, 'user_agent', user_agent FROM connections WHERE direction != 'in' AND user_agent != '');
DELETE FROM facts WHERE id IN (
    SELECT f.id FROM inbound_ids x
    JOIN entities e ON e.kind = x.kind AND e.key = x.key
    JOIN facts f ON f.rel = x.rel AND f.src = x.dev AND f.dst = e.id);
DROP TABLE temp.inbound_ids;

-- Hourly rollups gain the direction, and key an inbound connection by the
-- device's port (the service) rather than the initiator's ephemeral one.
-- Rollups still covered by raw connections take both from them; older ones
-- stay as they were, counted as outbound.
CREATE TABLE traffic_hourly_new (
    bucket        INTEGER NOT NULL,
    client_device INTEGER NOT NULL,
    client_ip     TEXT    NOT NULL,
    remote_ip     TEXT    NOT NULL,
    remote_port   INTEGER NOT NULL, -- the server's port: the device's own for direction 'in'
    proto         INTEGER NOT NULL,
    name          TEXT    NOT NULL,
    direction     TEXT    NOT NULL DEFAULT 'out',
    app           TEXT    NOT NULL,
    multicast     INTEGER NOT NULL,
    flows         INTEGER NOT NULL,
    bytes_out     INTEGER NOT NULL,
    bytes_in      INTEGER NOT NULL,
    PRIMARY KEY (bucket, client_device, client_ip, remote_ip, remote_port, proto, name, direction)
) WITHOUT ROWID;

CREATE TEMP TABLE conn_tuples AS
SELECT client_device, client_ip, remote_ip, remote_port, proto, min(direction) AS direction, min(client_port) AS client_port
FROM connections GROUP BY 1, 2, 3, 4, 5;

INSERT INTO traffic_hourly_new (bucket, client_device, client_ip, remote_ip, remote_port, proto, name, direction, app, multicast, flows, bytes_out, bytes_in)
SELECT t.bucket, t.client_device, t.client_ip, t.remote_ip,
    CASE WHEN c.direction = 'in' THEN c.client_port ELSE t.remote_port END,
    t.proto, t.name, coalesce(c.direction, 'out'), max(t.app), max(t.multicast), sum(t.flows),
    sum(CASE WHEN c.direction = 'in' THEN t.bytes_in ELSE t.bytes_out END),
    sum(CASE WHEN c.direction = 'in' THEN t.bytes_out ELSE t.bytes_in END)
FROM traffic_hourly t
LEFT JOIN conn_tuples c ON c.client_device = t.client_device AND c.client_ip = t.client_ip
    AND c.remote_ip = t.remote_ip AND c.remote_port = t.remote_port AND c.proto = t.proto
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8;

DROP TABLE temp.conn_tuples;
DROP TABLE traffic_hourly;
ALTER TABLE traffic_hourly_new RENAME TO traffic_hourly;
