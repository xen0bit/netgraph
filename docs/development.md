# Development

## Layout

| Path | |
|---|---|
| `cmd/netgraph-sensor` | the router agent. Must never import SQLite, d2 or the TUI libraries: `deps_test.go` enforces it (modernc SQLite does not build for MIPS, d2 adds ~20 MB) |
| `cmd/netgraph` | server, CLI, TUI |
| `cmd/web` | the WASM engine (`js && wasm`) |
| `internal/wire` | event schema, batch codec, shipper (spool, retry) |
| `internal/decode` | protocol parsers: DNS/mDNS/LLMNR/NBNS, DHCPv4/v6, ARP/NDP, LLDP, SSDP, HTTP, TLS ClientHello + JA4, QUIC Initial |
| `internal/flow` | the flow table and interval export |
| `internal/capture` | AF_PACKET (pure Go, TPACKET_V3), pcap/pcapng, radiotap/802.11 link types |
| `internal/sensor` | frame parsing, dispatch, DNS matching, dedupe, runners |
| `internal/rdns` | bounded background reverse-DNS lookups at observation time |
| `internal/wifi` | 802.11/radiotap parsing, WEP/WPA/WPA2 key derivation and decryption, channel hopping |
| `internal/store` | SQLite schema, ingest and correlation, queries, retention |
| `internal/graph`, `internal/graph/d2render` | graph assembly and d2 rendering |
| `internal/api`, `internal/apiclient` | HTTP server and client (`model.Backend`) |
| `internal/model` | API types, shared with WASM |
| `internal/tui` | the terminal UI |
| `internal/oui` | the embedded IEEE MAC registry (`make oui.update`) |
| `internal/testutil` | scripted pcap scenarios built with real implementations |
| `web/` | the browser UI (`src/`; `make web.build` assembles `dist/`) |
| `test/lab` | the Docker lab |
| `deploy/`, `packaging/` | Dockerfiles, compose files, systemd units, OpenWrt init |

## Building

```sh
make build         # bin/netgraph (no embedded UI) and bin/netgraph-sensor
make build-full    # bin/netgraph with the web UI and ASN table embedded (needs Go, gzip and curl)
make asn.fetch     # download the ASN table builds embed, if missing (make asn.update: again)
make cross         # compile every release target
make demo          # demo capture, database and server on 127.0.0.1:8443
```

Release builds embed two things a plain `go build` or `go install`
leaves out, each behind a build tag: the web UI (`embed_web`, from
`web/dist`) and the ASN table (`embed_asn`, from
`internal/asn/ip2asn-combined.tsv.gz`, which `make asn.fetch` downloads
and git ignores). `deploy/Dockerfile` embeds the table only when it is
already in the build context, so the lab never downloads it.

Everything is `CGO_ENABLED=0`. Before adding a dependency, check that
`make cross` still passes and that the sensor still builds for `mipsle`.
The target lists live in the Makefile, `.goreleaser.yaml` and CI's
`cross` job. Change all three together.

## Testing

```sh
make test          # unit and integration tests, -race
make lint          # gofmt, go vet (all tag sets), golangci-lint
make fuzz          # every Fuzz target for FUZZTIME (20s)
make lab           # the Docker lab (below)
NETGRAPH_SCALE=1 go test -run TestScale -v ./internal/store/   # load test with timings
```

The tests replay captures built by `internal/testutil`: a scripted home
network whose ClientHellos come from `crypto/tls` and whose QUIC Initials
are sealed with the RFC 9001 keys, so the sensor, the store, the API and
the TUI are tested end to end against exact expectations.
`internal/sensor/testdata/curl-clienthello.pcap` pins JA4 against values
Wireshark 4.6 computed. `go run ./internal/testutil/genpcap out.pcap`
writes the scenario for manual use.

`internal/wifi` pins AES-CCM against RFC 3610 packet vector #1 and the WPA
PMK against the 802.11i passphrase vector, then checks CCMP/TKIP/WEP
round-trips and a complete EAPOL 4-way handshake. `make fuzz` covers the
radiotap/802.11 parsers; a panic on a malformed frame is a bug, not an
expected drop.

### The Docker lab

`test/lab/compose.yml` is a home network with no route to the internet:
a router running dnsmasq (DHCP, DNS) with the sensor in its network
namespace, an avahi printer, a Samba NAS, an SSDP TV, lldpd, a web server
speaking TLS, HTTP/3 and HTTP behind the router, and a laptop that runs
`udhcpc`, `dig`, `curl` and a quic-go client on a script, including a
90-second connection that spans several windows.

`make lab` (`go test -tags lab ./test/lab`) builds the images, waits for
the script, and then:

- checks devices, names, fingerprints, DNS, connections and window states
  through the API;
- runs `tshark` on the lab's own capture and checks every TLS and QUIC JA4
  against netgraph's;
- replays that capture into a fresh database and checks it learns the
  same names;
- drives the web UI in headless Chrome (graph drawn by WASM, details
  panel, every table);
- runs `deploy/compose/sidecar.yml` as written, with the lab's images.

`NETGRAPH_LAB_KEEP=1` leaves the lab running (server on
`127.0.0.1:18443`, read token `lab-read-token`). `NETGRAPH_SHOTS=dir`
keeps the browser screenshots.

## Releasing

Tag `vX.Y.Z` and push. The release workflow runs the tests, builds every
target with goreleaser (archives, deb/rpm/apk, multi-arch images on GHCR),
signs the checksums with cosign (keyless) and attaches SBOMs. CI runs the
same pipeline as a snapshot on every pull request.
