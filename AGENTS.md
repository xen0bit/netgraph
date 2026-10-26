# AGENTS.md — working on netgraph

Read `docs/development.md` for the layout, builds and tests, and
`docs/concepts.md` for what the data means. The rules below are the ones
that are easy to break.

## Invariants

- **The sensor stays small and portable.** `cmd/netgraph-sensor` must not
  import SQLite, d2, the TUI libraries or `gopacket/layers`;
  `cmd/netgraph-sensor/deps_test.go` checks the first three. It must build
  for every target in `SENSOR_TARGETS` (MIPS softfloat, ARMv5 included):
  run `make cross`.
- **Everything is `CGO_ENABLED=0`.** The target lists live in the
  Makefile, `.goreleaser.yaml` and the CI `cross` job. Change all three
  together.
- **Windows are half-open `[from, to)`.** A connection belongs to a
  window if a record overlaps it. Bytes straddling an edge are prorated;
  states are `carried` (opened before `from`), `opened`, plus `closed`.
  DNS answers are valid for `[ts, ts+ttl]`.
- **Flow records span at most `store.MaxRecordSpan`** (10 min; ingest
  splits longer ones). Window queries over `flows` depend on it to bound
  `t_end` on both sides (`flowsWindow`). Queries over `connections` read
  totals and prorate only edge-crossing connections (`connBytes`).
- **Replays are deterministic.** The flow table walks its LRU list, never
  a map, and DNS timeouts are sorted: replaying a capture twice gives
  identical events (`TestReplayDeterministic`). Active lookups — reverse
  DNS, channel hopping — are live-capture only.
- **The sensor persists nothing.** It writes no file: no database, spool,
  cache or keyring on disk. Its only inputs from disk are the token and CA
  files it is pointed at.
- **Wi-Fi keys are configured on the server; decryption happens on the
  sensor, in pure Go.** `netgraph serve -wifi-key-file` holds the
  passphrases, derives PMKs (`internal/wifi`), and serves only PMKs and WEP
  keys on `GET /api/v1/wifi/keys` — with the ingest token, never under
  `-no-auth`. The sensor keeps them in memory and derives PTKs there. Keys
  flow one way: no key leaves the sensor (not the PMK, PTK, GTK or a MIC), and
  `wifi` events never carry one. The one thing a sensor sends is a
  `wifi_key` event's handshake **nonces** (ANonce/SNonce), broadcast in the
  clear during the 4-way handshake, which the server stores
  (`wifi_handshakes`) and serves back so a restarted or additional sensor
  can re-derive the PTK. The key file is never copied into the database.
  WPA3/SAE and 802.1X are parsed but need a supplied PMK; never fake a
  handshake result.
- **Decoders are pure functions over bytes from the network**, which is
  attacker-controlled: bound every length, never loop on input, and give
  each a `Fuzz*` target. The processor also recovers from panics, but a
  panic is still a bug.
- **Everything shown in the web UI goes through `esc()` or `textContent`.**
  Hostnames, user agents and UPnP strings come from the LAN.
- **d2 keys are always quoted** (`graph.quote`): an unquoted
  `example.com` or address is parsed as nested containers.
- **Correlation is by evidence.** Devices are found by the MAC that sent
  the packets. mDNS records go to the device holding their address, not
  the sender. DNS names prefer the lookup the connection's own SNI/Host
  names. Keep it that way: the lab caught each of these going wrong.

## Checks before a commit

```sh
gofmt -l .        # must print nothing
make lint test    # vet (default, lab and wasm tags), golangci-lint, tests with -race
make cross        # when touching dependencies or the sensor
make lab          # when touching capture, decoding, ingest, queries or the web UI
```
