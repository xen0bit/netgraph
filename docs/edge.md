# netgraph-edge (preview)

`netgraph-edge` runs VPN listeners whose traffic reports itself. A sensor on
a router sees a VPN as one encrypted connection to the tunnel's endpoint. The
edge is the tunnel's endpoint, so it knows two things nothing else does:

- **who** each session is: the identity the protocol's handshake proved (a
  WireGuard public key, a username, a certificate's subject), the inner
  address it was given, and where it connected from; and
- **what** it did: the edge captures the inside of each tunnel with the
  sensor's own processor, so flows, DNS lookups, SNI, ALPN and fingerprints
  are recorded as a sensor would record them.

The server attributes each flow to the session that held its client address
when the flow began, on the edge that reported both.

```
wg-client ══ WireGuard ══► netgraph-edge ──► the inside network
                            │  session: gjMMARO…= holds 10.10.10.2/32, from 198.18.1.50
                            │  flows:   10.10.10.2 → 10.78.0.30:5201  1.7 MB
                            └──────────► netgraph serve  (ingest token, like a sensor)
```

The protocols come from `vpn/`, sixteen of them, each with a client and a
server (see [`vpn/README.md`](../vpn/README.md)). Any of them can run on an
edge. In this preview only **WireGuard** (and AmneziaWG) reports sessions, so
only its traffic is attributed to users. The others are captured and stored,
and the edge says once, per protocol, that they are not attributed yet.

## Running it

```sh
netgraph-edge run -server https://netgraph.example:8443 -token-file /etc/netgraph-edge/token \
    -listeners /etc/netgraph-edge/listeners
```

It needs `CAP_NET_ADMIN` (TUN devices, addresses, iptables), `CAP_NET_RAW` (its
capture of each TUN) and `/dev/net/tun`. It authenticates to the server with
the **ingest token**, as a sensor does, and appears in the sensor list under
`-name`.

Each JSON file in `-listeners` is one listener. `options` are exactly the
options `veepin serve <protocol>` takes (each protocol's page in
[`vpn/doc/usage`](../vpn/doc/usage) lists them). With `setup_nat`, the edge
addresses the TUN, enables forwarding and NATs the tunnel subnet out of `wan`
with iptables rules tagged with the listener's name, and removes them when the
listener stops.

```json
{
  "name": "office",
  "protocol": "wireguard",
  "setup_nat": true,
  "wan": "eth1",
  "options": {
    "private-key": "…",
    "address": "10.10.10.1/24",
    "listen-port": "51820",
    "peer-public-key": "…",
    "peer-allowed-ips": "10.10.10.2/32"
  }
}
```

`SIGHUP` re-reads the directory. A new file starts a listener, a deleted one
stops it, and a changed one restarts only that listener.
Listener files hold keys: keep the directory `0700` and its files `0600`.

## What a session is

A session opens when a handshake proves an identity and closes when that
identity stops holding the tunnel:

| Protocol | Opens | Identity | Closes |
|---|---|---|---|
| WireGuard, AmneziaWG | a handshake while none is open | the peer's public key | its keys pass reject-after-time (180 s) with no rekey, timed at its last authenticated packet; or the listener stops |

Every open session closes as `shutdown` when the edge stops. A flow is
attributed only to a session on the same edge, by address and time: a flow
seen by another sensor, a flow from before the session opened or after it
closed, and a flow from an address the session did not hold are not.

## Reading it

- `GET /api/v1/vpn/sessions?from=&to=` lists the sessions that overlap the
  window, with the flows and bytes attributed to each (see
  [api.md](api.md)).
- `flows.vpn_session` and `connections.vpn_session` hold the attribution in
  the database.

Sessions follow the raw records for retention, and `db purge` removes them.
`db forget` works by MAC, and a VPN user has none, so it cannot find them yet.

## Not yet

This is the first slice of the edge (see AGENTS.md, "vpn/ and the edge"):

- Sessions for the other fifteen protocols.
- Users and groups in the server, with policy compiled to the edge's own
  firewall table.
- Config the server signs and pushes, so the listener files go away.
- The web UI for sessions and users.
