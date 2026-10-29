-- The network (autonomous system) and country of a connection's remote end,
-- from the server's -asn-file. NULL means not looked up yet: a server
-- without the file leaves remote ends NULL, and they are filled in when one
-- is loaded. 0 means looked up and not routed, or a local or group address.

ALTER TABLE connections ADD COLUMN remote_asn INTEGER;
ALTER TABLE connections ADD COLUMN remote_cc TEXT NOT NULL DEFAULT '';
CREATE INDEX connections_asn ON connections (remote_asn, last_seen);

ALTER TABLE traffic_hourly ADD COLUMN remote_asn INTEGER;
ALTER TABLE traffic_hourly ADD COLUMN remote_cc TEXT NOT NULL DEFAULT '';
CREATE INDEX traffic_hourly_asn ON traffic_hourly (remote_asn, bucket);

-- Connections and rollups already stored that cannot have a network.
UPDATE connections SET remote_asn = 0 WHERE direction = 'local' OR multicast = 1;
UPDATE traffic_hourly SET remote_asn = 0 WHERE direction = 'local' OR multicast = 1;
