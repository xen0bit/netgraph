-- Query indexes for the filters and anomaly checks that scan by direction
-- and by either address. The window condition still drives the time index;
-- these narrow the rows SQLite considers for a slow query.
CREATE INDEX connections_direction ON connections (direction, last_seen);
CREATE INDEX connections_client_ip ON connections (client_ip, last_seen);
CREATE INDEX connections_remote_ip ON connections (remote_ip, last_seen);

CREATE INDEX dns_answers_expires_data ON dns_answers (expires, data);
CREATE INDEX observations_type ON observations (type, ts);
