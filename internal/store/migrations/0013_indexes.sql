-- The entity timeline looks up observations by address, and DNS filters
-- often start from the client address. Both scanned the whole window.
CREATE INDEX observations_ip ON observations (ip, ts);
CREATE INDEX dns_client_ip ON dns (client_ip, ts);
