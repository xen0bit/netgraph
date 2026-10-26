-- An access point's group keys (GTKs) as it sent them to a client: the
-- EAPOL-Key fields with the key data still wrapped by that client's KEK, plus
-- the client's handshake nonces. No usable key is stored; a sensor re-derives
-- the KEK from its own PMK and unwraps the GTK, so a restarted or additional
-- sensor decrypts the AP's broadcasts without waiting for the next rekey.
-- One row per (AP, key ID); the most recent wins.
CREATE TABLE wifi_group_keys (
    bssid       TEXT NOT NULL,
    key_id      INTEGER NOT NULL,       -- 0..3
    sta         TEXT NOT NULL,          -- the client whose KEK wraps it
    ssid        TEXT NOT NULL,
    anonce      TEXT NOT NULL,          -- hex
    snonce      TEXT NOT NULL,          -- hex
    descriptor  INTEGER NOT NULL,       -- 2 RSN, 254 WPA
    key_info    INTEGER NOT NULL,
    key_length  INTEGER NOT NULL,
    iv          TEXT NOT NULL,          -- hex, 16 bytes
    key_data    TEXT NOT NULL,          -- hex, wrapped
    sensor_id   INTEGER,
    ts          INTEGER NOT NULL,       -- when the AP sent it (unix ms)
    PRIMARY KEY (bssid, key_id)
);
