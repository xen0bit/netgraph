-- Public WPA 4-way-handshake nonces, shipped by sensors so that a restarted
-- or additional sensor can re-derive pairwise keys without having to
-- re-capture the handshake. ANonce and SNonce are broadcast in the clear
-- during the handshake, so these are not secrets; no key or raw frame is
-- stored here, so these rows cannot by themselves decrypt any traffic. One
-- row per (AP, station); the most recent handshake wins.
CREATE TABLE wifi_handshakes (
    bssid       TEXT NOT NULL,          -- access point MAC
    sta         TEXT NOT NULL,          -- client station MAC
    ssid        TEXT NOT NULL,          -- network name (to find the PMK)
    anonce      TEXT NOT NULL,          -- authenticator nonce, hex
    snonce      TEXT NOT NULL,          -- supplicant nonce, hex
    key_version INTEGER NOT NULL,       -- EAPOL descriptor version: 1 TKIP, 2 CCMP
    sensor_id   INTEGER,                -- which sensor observed it
    ts          INTEGER NOT NULL,       -- observation time (unix ms)
    PRIMARY KEY (bssid, sta)
);

CREATE INDEX wifi_handshakes_ts ON wifi_handshakes (ts);
