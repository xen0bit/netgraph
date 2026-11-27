# AGENTS.md — working on netgraph

Read `docs/development.md` for the layout, builds and tests, and
`docs/concepts.md` for what the data means. The rules below are the ones
that are easy to break.

## Invariants

- **The sensor stays small and portable.** `cmd/netgraph-sensor` must not
  import SQLite, d2, the TUI libraries, `gopacket/layers` or anything under
  `vpn/`; `cmd/netgraph-sensor/deps_test.go` checks all of them. It must build
  for every target in `SENSOR_TARGETS` (MIPS softfloat, ARMv5 included):
  run `make cross`.
- **Everything is `CGO_ENABLED=0`.** The target lists live in the
  Makefile, `.goreleaser.yaml` and the CI `cross` job. Change all three
  together. The one exception is the NetworkManager editor plugin in `vpn/nm`
  (its own Go module, with a GTK `.so` in C); its D-Bus service is still CGO-free.
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
- **Other sources run on the server** (`internal/sources`): decoders bound what they read
  and have `Fuzz*` targets, as the sensor's do, and UDP exports need an allow-list. Conntrack is the exception, since only the router's
  kernel knows it: `internal/conntrack` runs in the sensor, off by default.
- **The host agent is not the sensor.** `cmd/netgraph-agent` is optional (Linux, macOS, Windows);
  nothing else depends on it. It sends a program's name, not its arguments, unless `-cmdlines`,
  and runs nothing the server names. Each platform's parsers build everywhere, have `Fuzz*`
  targets, and are tested on Linux CI. A program is matched to a sensor's connection by
  protocol, both addresses and ports, while it was open: never guessed from a name or a time alone.
  An ICMP echo's identifier is its port (the sensor records it as the pinger's), and an unbound
  socket's source address is the one the agent's routing table gives. Its optional BPF programs
  (`internal/agent/linux/bpf`, `-events=bpf`) only read, report only the agent's own network
  namespace, read no payload past a UDP or ICMP header, and are rebuilt with `make bpf` and
  checked in: the agent builds without clang. A process named by an event is read from `/proc`
  only if its start time matches the kernel's.
- **The sensor persists nothing.** It writes no file: no database, spool,
  cache or keyring on disk. Its only inputs from disk are the token and CA
  files it is pointed at. (The kernel's connection table comes over netlink.)
- **The server can't do much to a sensor.** `wire.SensorConfig` is a short list of bounded
  settings, held in memory only: nothing in it may run anything, name a path, or change where
  data goes. Upgrades are prompted, never performed.
- **Wi-Fi keys are configured on the server; decryption happens on the
  sensor, in pure Go.** `netgraph serve -wifi-key-file` holds the
  passphrases, derives PMKs (`internal/wifi`), and serves only PMKs and WEP
  keys on `GET /api/v1/wifi/keys` — with the ingest token, never under
  `-no-auth`. The sensor keeps them in memory and derives PTKs there. Keys
  flow one way: no key leaves the sensor (not the PMK, PTK, GTK or a
  MIC), and `wifi` events never carry one. What a sensor does send, for a
  restarted or additional sensor to re-derive keys from its own PMK: a
  `wifi_key` event's handshake **nonces** (ANonce/SNonce, broadcast in the
  clear), stored in `wifi_handshakes`; and a `wifi_gtk` event's group key
  **as the AP sent it, still wrapped with the client's KEK**, plus that
  handshake's nonces, stored in `wifi_group_keys`. Never ship an unwrapped
  GTK. The key file is never copied into the database.
  WPA3/SAE, OWE and 802.1X need a supplied PMK, and nothing installs unless the
  handshake's MIC proves it; never fake a handshake result.
- **Decoders are pure functions over bytes from the network**, which is
  attacker-controlled: bound every length, never loop on input, and give
  each a `Fuzz*` target. The processor also recovers from panics, but a
  panic is still a bug.
- **Everything shown in the web UI goes through `esc()` or `textContent`.**
  Hostnames, user agents and UPnP strings come from the LAN.
- **The map keeps its places** (`web/src/js/map/`). A node with a known
  position never moves unless a person moves it or asks to re-arrange: new
  nodes give way. Don't add a layout step that shifts what is already placed.
- **The DNS server answers only who it may, and refuses only what's named.** `internal/dnsserver`
  runs only with `serve -dns-listen`; it answers clients in `-dns-allow` (default the private
  ranges, never the internet: others get a rate-limited REFUSED), refuses only names an enabled
  blocklist or a person's DNS rule matched (no default blocking), and never touches a firewall.
  Requests are bytes off the network: bound them and keep `FuzzHandle` passing. Upstream URLs
  are read from a file or the environment and shown by scheme and host only.
- **netgraph never touches a firewall** — with two opt-in exceptions. `internal/policy` only reads and writes text.
  The optional host agent (`netgraph-agent -enforce=nftables -apply`) may change its own host's
  firewall, and only in one table it owns and replaces whole: it drops only what an explicit,
  host-wide deny rule matched (never a default, never a rule for one program, never the server's
  address), dry-runs unless `-apply`, and removes its table on exit. An export
  is built from what's parsed or reduced to a safe alphabet, so a hostname can't add a rule, and
  anything it can't express is commented out and warned about: a dropped deny is a hole.
  The second is `netgraph-edge`, whose listeners with `"setup_nat"` address their TUN, enable
  forwarding and NAT the tunnel subnet out of the named WAN, with iptables rules tagged with the
  listener's name and removed when it stops (`vpn/internal/hostnet`, through the supervisor). It
  installs nothing else, and nothing the server sends can change that.
- **The archive follows erasure.** `internal/archive` holds what retention would delete, and
  `db forget` and `db purge` rewrite it, finding it from the database (`archive_location`). Retention
  only deletes what's safely in a file. Its rows carry no database ids, as those rows will be gone.
- **Every table has an erasure decision** in `tableErasure`
  (`internal/store/erasure_tables_test.go`): a new one fails that test until
  it's added to `db forget`, `db purge` and the disk guard as it needs.
- **Secrets stay out of what's logged.** Channel and broker URLs hold tokens: `Name()`
  and errors never repeat one (an http client's error quotes its URL), and they're
  read from files or the environment, not flags. Text off the network stays inert in
  a chat message or an email header.
- **AI gets read-only tools.** `internal/tools.Backend` has no method that writes, so
  neither MCP nor the LLM mode can change anything; keep it that way. A model's
  statement with no real tool call behind it is dropped (`llm.finish`). LLM use is off
  unless configured, and asked for per question, and a model off the network warns first.
- **Every route but ingest and the host agent's goes through `Server.require`** (the agent's use
  `requireAgent` and their own token, off when it's unset) with the least role it
  needs: reads are `RoleViewer`, changes `RoleOperator`. Until an operator or admin token
  exists, the read token does everything, so upgrading never changes who can do what. A
  proxy's user header counts only from `-trusted-proxy` addresses, and cookie-borne
  changes must pass `sameOrigin`.
- **d2 keys are always quoted** (`graph.quote`): an unquoted
  `example.com` or address is parsed as nested containers.
- **A device's type is a judgement.** `internal/classify` is a pure function over
  strings a device chose to send: bound what it reads, keep `FuzzClassify` passing,
  and return the reasons with the verdict. A person's answer beats it. Suggestions,
  such as linking a private MAC to a known device, change nothing until answered.
- **Correlation is by evidence.** Devices are found by the MAC that sent
  the packets. mDNS records go to the device holding their address, not
  the sender. DNS names prefer the lookup the connection's own SNI/Host
  names. Keep it that way: the lab caught each of these going wrong.

## vpn/ and the edge

`vpn/` is veepin, merged with its history: sixteen VPN protocols, client and
server. `vpn/AGENTS.md` holds the protocol rules (both roles, interop against a
real peer, parsers return subslices, a peer's address moves only on an
authenticated packet) and applies inside `vpn/`. It imports only the standard
library and `golang.org/x/{crypto,net,sys}` (`vpn/deps_test.go`). Outside
`vpn/`, only `internal/edge` and `cmd/netgraph-edge` import it, and the edge
never links `vpn/toy` (`cmd/netgraph-edge/deps_test.go`).

**`netgraph-edge` attributes by evidence, as the store does.** A server
reports a session (`client.SessionReporter`) only once its handshake has proved
an identity, under that identity, with the inner prefixes it holds. The store
attributes a flow to a session only on the edge that reported it, by address and
time (`[start, end)`, at the flow interval's start). It never guesses from a
name, and never attributes across sensors. A protocol that doesn't report sessions is
captured but not attributed, and the edge says so once.

Planned, not yet in force: an edge is a separate binary from the sensor. Only
the edge and the opt-in host agent may touch a firewall, each in tables it
owns. An edge applies only config signed by its enrolled controller,
commit-confirmed so a bad push rolls itself back. Nothing past TLS and a
protocol's own handshake is reachable before authentication. AI stays read-only
over all of it. These rules replace the matching invariants above when that
config arrives, and not before; today an edge's listeners are files on its own
disk.

## Checks before a commit

```sh
gofmt -l .        # must print nothing
make lint test    # vet (default, lab and browser tags), golangci-lint, tests with -race
make test32       # when touching decoders or packet paths (32-bit/softfloat)
make fuzz         # when touching a decoder (slow: FUZZTIME, 20s by default)
make cross        # when touching dependencies or the sensor
make browser      # when touching the web UI
make lab          # when touching capture, decoding, ingest, queries or the web UI
make vpn.interop VPN_RUN='<cells>'  # when touching vpn/ protocols (Docker)
make edge.lab     # when touching the edge, vpn/ sessions or their ingest (Docker)
```

`make test` also runs `go test ./vpn/...` a second time without `-race`, for
vpn/'s allocation guards. `make fuzz` covers vpn/'s ~75 targets too: use
`FUZZPKGS=./internal/...` or `./vpn/...` to fuzz only what you touched.
