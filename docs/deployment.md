# Deployment

A deployment is one **server** and one or more **sensors**. The server
holds the database, the API and the UIs. Each sensor captures somewhere on
the network and posts what it sees to the server. Sensors keep nothing on
disk.

```
 router                                   server
 ┌──────────────────────┐   HTTP(S) POST   ┌───────────────────────────────┐
 │ netgraph-sensor      │  zstd JSON lines │ netgraph serve                │
 │  AF_PACKET on br-lan │ ───────────────► │  SQLite, API, web UI on :8443 │
 └──────────────────────┘   bearer token   └───────────────────────────────┘
```

## Where to capture

Capture on the **LAN side** of the router, usually the bridge (`br-lan`
on OpenWrt, `br0` or `lan` elsewhere). There the sensor sees client
addresses before NAT, and the LAN broadcasts and multicasts that identify
devices (DHCP, mDNS, SSDP, NetBIOS, ARP).

The sensor sees what passes through the interface it captures:

- **LAN to internet**: yes, on the router.
- **Device to device on the same switch**: no. A switch forwards it
  directly and the router never sees it. Use a mirror (SPAN) port with
  `-promisc` if you need it.
- **Hardware-offloaded flows**: some routers' "hardware flow offloading"
  forwards established connections without the CPU, and no capture
  sees those packets. Software flow offloading is fine. Turn hardware
  offloading off if connections look truncated.

`-iface` takes interface names (`br-lan`, or several: `br-lan,wlan0`) or an
address or CIDR that the interface holds (`192.168.1.1`, `10.0.0.0/24`),
which survives interface renames. Do not list both a bridge and one of its
member ports, or packets are counted twice.

## The server

```sh
export NETGRAPH_TOKEN=$(openssl rand -hex 32)        # sensors present this
export NETGRAPH_READ_TOKEN=$(openssl rand -hex 32)   # optional: protects queries and the UI
netgraph serve -db /var/lib/netgraph/netgraph.db -listen :8443
```

| Flag | Default | |
|---|---|---|
| `-db` | `netgraph.db` (`$NETGRAPH_DB`) | database file; created and migrated on start |
| `-listen` | `:8443` (`$NETGRAPH_LISTEN`) | |
| `-token-file` | `$NETGRAPH_TOKEN` | ingest token; required unless `-no-auth` |
| `-read-token-file` | `$NETGRAPH_READ_TOKEN` | query token; when empty, queries and the UI are open (a warning is logged) |
| `-tls-cert`, `-tls-key` | | serve HTTPS |
| `-raw-retention` | `14d` | keep raw connections, lookups and observations |
| `-rollup-retention` | `180d` | keep hourly rollups and facts |
| `-exact-max` | `48h` | longer windows are answered from hourly rollups |
| `-fact-gap` | `1h` | silence after which a relationship starts a new period |
| `-web-dir` | | serve the UI from a directory instead of the embedded copy |

Retention runs hourly. Back up a live database with `netgraph db backup
-db netgraph.db backup.db`.

**Sizing.** Storage depends on how many connections the network makes. A
busy synthetic home (40 devices, 120k connections a day) needs about
280 MB of raw data per day. Typical homes are a fraction of that. With the
default 14 days of raw data and 180 days of rollups, plan for a few GB.

## The sensor

```sh
netgraph-sensor run -iface br-lan -server https://netgraph.lan:8443 -token-file /etc/netgraph/sensor.token
```

| Flag | Default | |
|---|---|---|
| `-iface` | `$NETGRAPH_IFACE` | names, or an address/CIDR the interface holds |
| `-pcap` | | replay a pcap/pcapng file instead |
| `-server` | `$NETGRAPH_SERVER` | server URL, or `-` to print JSON lines |
| `-token-file` | `$NETGRAPH_TOKEN` | |
| `-name` | hostname (`$NETGRAPH_SENSOR_NAME`) | how the server knows this sensor |
| `-ca-file`, `-insecure-skip-verify` | | for a server with a private CA or self-signed certificate |
| `-promisc` | off | for SPAN/mirror ports |
| `-active-timeout` | `30s` | how often long connections report; also the server's freshness lag |
| `-tcp-idle`, `-udp-idle` | `5m`, `60s` | silence after which a connection is considered gone |
| `-max-flows` | `65536` | tracked connections; about 720 B each |
| `-spool-mb` | `32` | batches held while the server is unreachable; oldest dropped beyond |
| `-mem-limit-mb` | `128` | Go soft memory limit (unless `$GOMEMLIMIT`) |
| `-ring-mb` | `8` | AF_PACKET ring per interface |
| `-rdns` | on | reverse DNS for local hosts while they are observed (live capture only) |
| `-rdns-timeout`, `-rdns-workers`, `-rdns-ttl` | `2s`, `4`, `1h` | lookup bound, concurrency and answer cache |
| `-wifi-key-file` | `$NETGRAPH_WIFI_KEY_FILE` | WPA/WPA2 passphrases, PMKs and WEP keys |
| `-wifi-hop`, `-wifi-channels`, `-wifi-dwell` | off, common 2.4/5 GHz, `250ms` | channel hopping on monitor interfaces |
| `-wifi-data` | off | emit one event per data frame (noisy; management and handshakes are always reported) |

Capturing needs `CAP_NET_RAW`. Run as root, use the systemd unit
(below), or grant the capability once:

```sh
sudo setcap cap_net_raw+ep /usr/bin/netgraph-sensor
```

The sensor ignores its own connection to the server. If the server is
unreachable it keeps capturing, holds up to `-spool-mb` of batches, and
delivers them in order when the server is back. Retried batches are
recognised and not counted twice.

Reverse DNS uses the system resolver (`/etc/resolv.conf`), which on a
router normally means dnsmasq and its DHCP leases. It runs only for live
capture, at most four lookups at once, and is turned off with `-rdns=false`.
A `-pcap` replay never performs active lookups, so replaying the same file
twice gives the same events.

### Wi-Fi capture

A monitor-mode interface gets 802.11 frames, so the sensor decodes Wi-Fi
natively (no bridge or router capture is needed):

```sh
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
netgraph-sensor run -iface mon0 -server https://netgraph.lan:8443 \
  -wifi-key-file /etc/netgraph/wifi.keys -wifi-hop -wifi-channels 1,6,11,36,40,44,48
```

`-wifi-hop` uses the wireless extensions ioctl. It works with ordinary
mac80211 monitor interfaces; 6 GHz channels and some fullmac drivers need a
fixed channel instead. The interface must already be in monitor mode; the
sensor never changes that.

Keys are read from a root-only file, never from flags, so they do not appear
in `ps` or a shell history:

```sh
sudo install -m 600 /dev/null /etc/netgraph/wifi.keys
sudo tee /etc/netgraph/wifi.keys >/dev/null <<'EOF'
# WPA/WPA2-PSK: <ssid> <passphrase or 64 hex digits>
wpa2 home correct horse battery staple
# WPA3/SAE or 802.1X: the PMK must be obtained out of band
pmk modern 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# WEP: <index 0-3> <5, 13 or 16 bytes of hex>
wep 0 0102030405
EOF
```

Open networks need no keys. WEP and WPA/WPA2-PSK are decrypted from the
air; WPA3/SAE, OWE and 802.1X have no passively derivable PMK and need a
`pmk` entry. Decrypted data frames enter the normal flow, DNS, TLS and HTTP
pipeline, so the connection graph looks the same as for a wired capture.
Wi-Fi events carry no key material.

If the interface is not in monitor mode, or no packets are 802.11, the
sensor treats it as Ethernet. Channel hopping is only started for
interfaces whose kernel link type is 802.11.

### OpenWrt

Download the `netgraph-sensor_<version>_linux_<arch>.tar.gz` that matches
your router (`mipsle` for most ramips/MT7621 boards, `mips` for ath79,
`armv7` for ipq40xx/mvebu, `arm64` for filogic/rockchip). Check with `uname -m`
and `opkg print-architecture`. Then:

```sh
scp netgraph-sensor root@router:/usr/bin/
scp openwrt/netgraph-sensor.init root@router:/etc/init.d/netgraph-sensor
scp openwrt/netgraph.config root@router:/etc/config/netgraph
ssh root@router '
  mkdir -p /etc/netgraph && echo "<token>" > /etc/netgraph/sensor.token
  uci set netgraph.sensor.server="http://192.168.1.10:8443"; uci commit netgraph
  /etc/init.d/netgraph-sensor enable && /etc/init.d/netgraph-sensor start'
```

The binary is about 8 MB. On routers with little flash, keep it in
`/tmp` (RAM) and fetch it at boot, or compress it with `upx --lzma`.

### Linux with systemd

The `.deb`, `.rpm` and `.apk` packages install `netgraph-sensor.service`
and `/etc/netgraph/sensor.conf`:

```sh
sudo apt install ./netgraph-sensor_<version>_linux_amd64.deb
sudoedit /etc/netgraph/sensor.conf     # NETGRAPH_SENSOR_ARGS=-iface br0 -server https://...
echo "<token>" | sudo tee /etc/netgraph/sensor.token >/dev/null && sudo chmod 600 /etc/netgraph/sensor.token
sudo systemctl enable --now netgraph-sensor
```

The units run as a dynamic, unprivileged user (the sensor with only
`CAP_NET_RAW`) and read tokens through systemd credentials, so the token
files can stay root-only. The server package installs `netgraph.service`
the same way: its token goes in `/etc/netgraph/server.token`, an optional
read token in `/etc/netgraph/read.token`, and the database lives in
`/var/lib/netgraph`.

## Docker

Images: `ghcr.io/xen0bit/netgraph` (server, with the web UI) and
`ghcr.io/xen0bit/netgraph-sensor`. The compose files in `deploy/compose/`
cover the three shapes:

- **`sidecar.yml`**: the sensor shares an application container's network
  namespace (`network_mode: service:app`) and sees its traffic. The lab
  tests run this file as written.
- **`host.yml`**: the sensor on a router or Linux host, with
  `network_mode: host`.
- **`server.yml`**: the server on its own.

The sensor needs only `cap_add: [NET_RAW]`; the examples drop everything
else and run read-only.

## Several sensors

Any number of sensors can ship to one server, each with its own `-name`
(set it explicitly: the default is the hostname, and two sensors on one host
would otherwise merge). The server learns each sensor's interface prefixes
and uses them, together with the private ranges, to decide which addresses
are local. Sequence numbers, boot IDs and flow IDs are scoped per sensor, so
two sensors can record the same flow ID without colliding; the `sensors`
query and the web UI's Sensors tab show each one's version, interfaces and
counters. Two sensors that see the same packets (say on both sides of a
bridge) record them twice, so capture each segment once.

## Securing it

- Always set `NETGRAPH_TOKEN`. Without it (`-no-auth`) anyone who can reach
  the port can write to your database.
- Set `NETGRAPH_READ_TOKEN` unless the server listens on a trusted network
  only. The data includes every device's browsing destinations.
- Use `-tls-cert`/`-tls-key`, or a reverse proxy, when sensors ship across
  networks you do not control.
