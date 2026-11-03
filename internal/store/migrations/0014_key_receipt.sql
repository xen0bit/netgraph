-- The server's receipt time, separate from the capture timestamp. Sensors
-- can replay an old batch after a delay; a handshake with an older capture
-- timestamp must not overwrite a newer one. Receipt time breaks ties when
-- two sensors report the same capture timestamp.
ALTER TABLE wifi_handshakes ADD COLUMN received INTEGER NOT NULL DEFAULT 0;
ALTER TABLE wifi_group_keys ADD COLUMN received INTEGER NOT NULL DEFAULT 0;
CREATE INDEX wifi_handshakes_received ON wifi_handshakes (received);
CREATE INDEX wifi_group_keys_received ON wifi_group_keys (received);
