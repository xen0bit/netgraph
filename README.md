# netgraph

Passive network visibility for a home or lab LAN, as a graph you can slice by
time. A small sensor on the router learns everything it can about the
network: flows, DNS lookups and answers with their TTLs, TLS/QUIC SNI, DHCP,
mDNS/DNS-SD, ARP/NDP, MAC vendors, hostnames and more. It ships these to a
server that stores them in SQLite as **entities and relationships over
time**. For any window `t0 → t1` you can ask which clients were on the
network, what they resolved, which hosts they were already connected to when
the window opened, which they connected to during it, and how much data
moved. The results come back as tables, as a terminal graph, or as a graph in
the browser.

> Status: early scaffolding. See [AGENTS.md](AGENTS.md) for the layout and
> roadmap.

## Components

| Binary | Runs on | Does |
|---|---|---|
| `netgraph-sensor` | the router (any Linux, mips/arm/x86, ~4 MB) | captures packets with pure-Go AF_PACKET, decodes them, streams events |
| `netgraph` | any host (Linux, macOS, Windows) | ingest, SQLite storage, correlation, query CLI, TUI, web UI |

## Deployment

- **Router or host:** install the sensor package, or use
  `deploy/compose/host.yml`. Capture on the LAN bridge (`br-lan`) so client
  addresses are seen before NAT.
- **Docker sidecar:** use `deploy/compose/sidecar.yml`. The sensor shares the
  network namespace of the container it watches.
- **OpenWrt:** the sensor tarball contains `openwrt/` with a procd init
  script and a UCI config.

The sensor needs `CAP_NET_RAW`.

## Development

```sh
make build     # bin/netgraph, bin/netgraph-sensor
make test      # unit tests, -race
make lint      # gofmt, vet, golangci-lint
make cross     # compile every release architecture
make lab       # isolated docker-compose end-to-end lab
```
