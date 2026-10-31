-- Anomaly checks scan by client/direction/first-seen and join has_ip facts
-- by destination. These keep the 24-hour report from becoming a table scan.
CREATE INDEX connections_client_direction ON connections (client_device, direction, first_seen);
CREATE INDEX connections_direction_first ON connections (direction, first_seen);
CREATE INDEX facts_rel_dst_src ON facts (rel, dst, src, first_seen, last_seen);
CREATE INDEX traffic_hourly_device_bucket ON traffic_hourly (client_device, bucket);
