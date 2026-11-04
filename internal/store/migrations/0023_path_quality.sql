-- What a TCP connection's handshake and retransmits say about the path.
ALTER TABLE connections ADD COLUMN rtt_server_us INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN rtt_client_us INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN retrans INTEGER NOT NULL DEFAULT 0;
