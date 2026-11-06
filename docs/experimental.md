# Experimental features

These features are built only with `-tags experimental` and are never part of
the default server, sensor or agent binaries.

## ECH observation

`netgraph-ech` observes TLS ClientHellos that carry the
`encrypted_client_hello` extension (0xfe0d). It reports:

- the outer SNI and ALPN,
- the JA4 fingerprint,
- the ECH type, config id and encrypted-payload length.

It **does not decrypt** the inner ClientHello and does not MITM TLS. ECH is
designed to hide the inner name, so an observer can only say that ECH was
present and that the outer name may not be the name the server serves.

```sh
make build-ech
./bin/netgraph-ech -pcap capture.pcap
# or, with CAP_NET_RAW:
sudo ./bin/netgraph-ech -iface eth0
```

Each output line is JSON with `ts`, `src`, `dst`, `link` and `observation`.

## BPF / AF_PACKET monitoring

`-iface` uses the same AF_PACKET TPACKET_V3 source as the sensor. It is a
packet monitor, not an enforcement path. Running it needs `CAP_NET_RAW`; it
only sees packets the host's interface receives.

## Control Center / menu bar

A macOS Control Center or menu-bar app is a separate companion application,
not part of netgraph core. It is not implemented here. Any such app should
talk to the normal API and must not be required for server operation.

## Safety

- Build tags keep experimental code out of default binaries.
- ECH observation is passive; no TLS decryption or interception.
- The live monitor needs explicit interface selection and privileges.
- Experimental code must not become an enforcement default.
