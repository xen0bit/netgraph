-- The pairwise cipher the station chose in message 2. Without it a sensor
-- that re-derives a key after a restart falls back to the beacon, which may
-- offer both CCMP and GCMP-256 (a transition network) and pick the wrong one.
ALTER TABLE wifi_handshakes ADD COLUMN cipher TEXT NOT NULL DEFAULT '';
