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
| `-read-token-file` | `$NETGRAPH_READ_TOKEN`; unit: `read.token` | query token; when empty, queries and the UI are open (a warning is logged) |
| `-tls-cert`, `-tls-key` | unit: `tls.crt`, `tls.key` | serve HTTPS |
| `-wifi-key-file` | `$NETGRAPH_WIFI_KEY_FILE`; unit: `wifi.keys` | WPA/WPA2 passphrases, PMKs and WEP keys for Wi-Fi sensors ([Wi-Fi capture](#wi-fi-capture)); needs an ingest token |
| `-raw-retention` | `14d` | keep raw connections, lookups and observations |
| `-rollup-retention` | `180d` | keep hourly rollups and facts |
| `-exact-max` | `48h` | longer windows are answered from hourly rollups |
| `-fact-gap` | `1h` | silence after which a relationship starts a new period |
| `-asn-file` | `$NETGRAPH_ASN_FILE`; release builds: built in | an ASN table: the network and country of remote addresses ([networks](#networks-and-countries)); `none` for no table |
| `-alert-webhook` | `$NETGRAPH_ALERT_WEBHOOK` | POST a JSON alert when a new device joins, and optionally for anomalies ([alerts](#new-device-alerts)) |
| `-alert-learn` | `24h` | learn the network this long after the first sensor connects before alerting on new devices |
| `-alert-anomalies` | | also POST anomalies at or above this severity: `low`, `medium` or `high`; repeats of one finding are cooled down for an hour |
| `-web-dir` | | serve the UI from a directory instead of the embedded copy |

"unit:" defaults apply under the packaged systemd unit, which hands the
server the files in `/etc/netgraph` ([Linux with systemd](#linux-with-systemd)).

Retention runs hourly. Back up a live database with `netgraph db backup
-db netgraph.db backup.db`; for a disk emergency, `netgraph db purge
'2026-10-01'` drops everything older than that time without changing the
retention settings. `netgraph db forget MAC` removes one device and all of
its history.

### Monitoring

`GET /metrics` serves Prometheus metrics, behind the read token when one
is set. Sensors report their counters to the server, so one scrape covers
every sensor, labelled `sensor="<name>"`:

```yaml
scrape_configs:
  - job_name: netgraph
    scheme: https
    authorization: { credentials_file: /etc/prometheus/netgraph.token }
    static_configs: [{ targets: ["netgraph.lan:8443"] }]
```

Worth alerting on: `time() - netgraph_sensor_last_seen_timestamp_seconds`
(a sensor went quiet), `rate(netgraph_sensor_kernel_drops_total[5m])`
(capture overload), `rate(netgraph_sensor_events_dropped_total[5m])` (the
server was unreachable longer than the spool lasts), and
`netgraph_ingest_errors_total`.

### Networks and countries

With an ASN table, the server records which network (autonomous system)
and country each remote address belongs to: a web server's visitors read
as `AS24940 HETZNER-AS · DE` instead of bare addresses, the graph draws
them one node per network, and queries filter with `asn:` and `cc:`
([usage](usage.md#choosing-a-window)). The table is
[iptoasn.com](https://iptoasn.com)'s `ip2asn-combined.tsv.gz` (IPv4 and
IPv6, public domain under the PDDL, updated hourly). The server never
fetches it itself.

**Release binaries, packages and images have one built in**, downloaded
when the release was built: nothing to set up. It costs about 9 MB of
binary, 30 MB of memory and a third of a second at start; the log says
`using the built-in asn table` with the day it was downloaded.
`-asn-file none` turns it off.

**A newer table**, or one for a build without it (`go install`, `go
build`), is a file and a flag:

```sh
sudo mkdir -p /usr/local/share/netgraph
sudo curl -fsSLo /usr/local/share/netgraph/ip2asn-combined.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz
netgraph serve -asn-file /usr/local/share/netgraph/ip2asn-combined.tsv.gz ...
```

A file replaces the built-in table. The server reloads it when it changes
(it checks every 5 minutes) or on `SIGHUP`, so a weekly timer keeps it
fresh:

```ini
# /etc/systemd/system/netgraph-asn.service
[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsSLo /usr/local/share/netgraph/ip2asn-combined.tsv.gz.new https://iptoasn.com/data/ip2asn-combined.tsv.gz
ExecStart=/usr/bin/mv /usr/local/share/netgraph/ip2asn-combined.tsv.gz.new /usr/local/share/netgraph/ip2asn-combined.tsv.gz

# /etc/systemd/system/netgraph-asn.timer
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
```

Under the packaged unit, keep the file **out of `/etc/netgraph`**: the unit
hands that directory to the server as systemd credentials, which are capped
at about 1 MB in all, and a larger file stops the unit from starting. Pass
`-asn-file` in `server.conf` instead. In Docker, mount the file read-only
and pass the flag.

Connections stored before a table was loaded (or by a server without one)
are looked up when it loads; `netgraph db enrich` does the same for a
database offline, with the built-in table or `-asn-file`. The networks'
names are kept in the database, so `netgraph query` reading the file shows
them without the table.

### New-device alerts

With `-alert-webhook URL`, the server posts an alert the first time a
device uses an address on the LAN: a phone, laptop or plug joining your
network. Devices merely heard over the air by a Wi-Fi sensor (access
points, passers-by probing for networks) do not count, and neither does the
router itself. For `-alert-learn` (default `24h`) after the first sensor
connects nothing is sent, so a new install learns the house quietly; the
devices already in an upgraded database are never reported.

The body is JSON that Slack, Mattermost and Discord webhooks accept as-is,
and that anything else can read:

```json
{"event": "new_device",
 "text": "New device on the network: alice-iphone (192.168.1.23, 3c:22:fb:01:02:03, Apple, Inc.)",
 "content": "…same as text…",
 "device": {"id": "device:3c:22:fb:01:02:03", "mac": "3c:22:fb:01:02:03", "label": "alice-iphone",
            "vendor": "Apple, Inc.", "ip": "192.168.1.23", "sensor": "router", "ts": "2026-10-26T12:00:00Z"},
 "allowed_mentions": {"parse": []}}
```

Device names come from the LAN, so the text has mentions (`@everyone`),
markup (`<!channel>`) and control characters neutralised; `device` carries
the raw values. Delivery is retried three times with backoff; alerts are
not stored, so ones queued when the server stops are lost.

With `-alert-anomalies medium` (or `low`/`high`) the same webhook also gets
an `event: "anomaly"` payload, with the finding in `anomaly` and the same
inert one-line `text`. The notifier checks the last hour every five minutes
and cools down a repeated finding for an hour, so a persistent scan does
not page continuously.

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
| `-flush` | `2s` | send batches at least this often |
| `-log-level`, `-log-format` | `info`, `text` | `debug`/`info`/`warn`/`error`; `text` or `json` (the server takes the same two) |
| `-mem-limit-mb` | `128` | Go soft memory limit (unless `$GOMEMLIMIT`) |
| `-ring-mb` | `8` | AF_PACKET ring per interface |
| `-rdns` | on | reverse DNS for local hosts while they are observed (live capture only) |
| `-rdns-timeout`, `-rdns-workers`, `-rdns-ttl` | `2s`, `4`, `1h` | lookup bound, concurrency and answer cache |
| `-wifi-hop`, `-wifi-channels`, `-wifi-dwell` | off, common 2.4/5 GHz, `250ms` | channel hopping on monitor interfaces |
| `-wifi-data` | off | emit one event per data frame (noisy; management and handshakes are always reported) |

Before starting a sensor, `netgraph-sensor check -iface br-lan -server
https://netgraph.lan:8443 -token-file ...` resolves the interface, opens it
with `CAP_NET_RAW`, prints the kernel link type (including monitor mode),
checks `/healthz`, and verifies that the ingest token can fetch Wi-Fi keys.

Capturing needs `CAP_NET_RAW`. Run as root, use the systemd unit
(below), or grant the capability once:

```sh
sudo setcap cap_net_raw+ep /usr/bin/netgraph-sensor
# Wi-Fi channel hopping (-wifi-hop) also needs CAP_NET_ADMIN:
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/netgraph-sensor
```

File capabilities are ignored on a `nosuid` mount (such as many `/tmp`
setups), so install the binary on a normal filesystem.

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

A monitor-mode interface gives the sensor raw 802.11 frames, so it decodes
Wi-Fi natively — no bridge or router capture needed. This sees what a wired
sensor cannot: beacons, probe requests, (re)associations, deauth/disassoc,
signal strength and nearby/rogue APs, plus, for WPA2-PSK networks whose
passphrase you hold, the decrypted traffic itself.

**Put the interface into monitor mode.** The adapter and its driver must
support monitor mode (`iw phy <phyN> info` should list `* monitor` under
"Supported interface modes"). Then:

```sh
# Stop NetworkManager (or wpa_supplicant) from managing the adapter, or it
# will reset monitor mode mid-capture. This is the most common failure.
sudo nmcli dev set wlan1 managed no

sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo iw dev wlan1 set channel 6         # or let -wifi-hop manage it
iw dev wlan1 info | grep -E 'type|channel'   # expect: type monitor
```

The sensor never changes the interface type; it only sets the channel (with
`-wifi-hop`). Run it against the monitor interface:

```sh
netgraph-sensor run -iface wlan1 -server https://netgraph.lan:8443 \
  -wifi-hop -wifi-channels 1,6,11,36,40,44,48,149
```

**Hopping vs. pinning.** `-wifi-hop` tunes the wireless extensions ioctl
(`SIOCSIWFREQ`) through the channel list, dwelling `-wifi-dwell` (default
250 ms) on each. Hopping is the right default for open-ended monitoring: a
key learned from a 4-way handshake is kept for the whole session, so once a
client's handshake is captured the sensor decrypts that client's traffic on
any channel from then on — leaving a channel and returning does **not**
invalidate the key. What hopping costs is only the chance of being on a
client's channel at the moment it associates; since clients associate rarely
and then stay connected, a single pass will not catch every handshake, but
coverage accumulates over time as devices reboot, reconnect and roam. A key
only goes stale if that client re-associates (a new handshake, a new key)
while the sensor is on another channel. To capture a *specific* network's
handshake within a short window — for example when you deliberately trigger a
reconnect — **pin to its channel** instead (`-wifi-channels <ch>` with one
channel, or set a fixed channel with `iw` and omit `-wifi-hop`). Hopping
works for ordinary mac80211 interfaces on 2.4 and 5 GHz; 6 GHz and some
fullmac drivers need a fixed channel.

A dual-band SSID runs a separate AP (and BSSID) per band, often on very
different channels. Decryption is per-AP, so pin to the band/channel the
target device actually uses — many clients prefer 5 GHz.

**Keys are configured on the server**, never on the sensor: the sensor has
no key file and writes nothing to disk. Give `netgraph serve` a root-only
key file with `-wifi-key-file` (never flags, so keys do not appear in `ps`
or a shell history). The server turns each passphrase into its PMK and
serves the PMKs and WEP keys — not the passphrases — to sensors that present
the ingest token. A sensor fetches them into memory before it starts
capturing and again every minute. After editing the file, send the server
`SIGHUP` (`kill -HUP`, or `docker kill -s HUP <container>`) to reload it
without a restart; a file that fails to parse is logged and the previous
keys stay in use. The change reaches every sensor within a minute, and a
removed network's keys are dropped from the sensors' memory. Because
the PMKs travel to the sensors, serve over HTTPS (`-tls-cert`) or a TLS
proxy unless the sensor link is trusted; the server warns otherwise. One
line per *distinct SSID* (the WPA2 key is derived from the passphrase and
the SSID, so the same SSID on both bands needs only one line):

```sh
# on the server
sudo mkdir -p /etc/netgraph
sudo install -m 600 /dev/null /etc/netgraph/wifi.keys
sudo tee /etc/netgraph/wifi.keys >/dev/null <<'EOF'
# WPA/WPA2-PSK: <ssid> <passphrase or 64 hex digits>. The passphrase is the
# rest of the line, so it may contain spaces; the SSID may not.
wpa2 home-iot correct horse battery staple
# WPA3/SAE or 802.1X: see below. A PMK is <ssid> <64 hex digits>.
pmk some-eap-net 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# WEP: <index 0-3> <5, 13 or 16 bytes of hex>
wep 0 0102030405
EOF
netgraph serve -token-file /etc/netgraph/server.token -wifi-key-file /etc/netgraph/wifi.keys ...
```

With the systemd unit, drop the file at `/etc/netgraph/wifi.keys`; the
unit loads it as a credential and the server uses it without a flag.
systemd copies credentials when the service starts, so after editing the
file use `systemctl restart netgraph` rather than a reload.

**What can be decrypted — WPA2-PSK yes, WPA3-SAE no.** For WPA2-PSK the
pairwise master key is `PBKDF2(passphrase, SSID)`, a static value, so knowing
the passphrase and capturing a client's 4-way handshake is enough to derive
its keys and decrypt its traffic. WEP likewise. **WPA3-SAE is different by
design**: the master key comes from an ephemeral per-session Dragonfly
exchange, so even with the passphrase a passive observer cannot derive it
(this is SAE's forward secrecy). OWE (open WPA3) is the same. These show up
fully in management and handshake events but their data is not decryptable;
a `pmk` entry only helps if you obtain that session's PMK out of band (and
for SAE the PMK changes every association). **WPA2/WPA3 "transition" networks
are decryptable per client:** a device that joins over WPA2-PSK can be
decrypted; one that chooses SAE (most modern phones) cannot, on the same
SSID.

For WPA3 devices, capture on the **router/bridge with a wired sensor**
instead — there the AP has already decrypted the traffic. The Wi-Fi sensor's
strengths are WPA2-PSK/IoT decryption and the layer-2 visibility a wired
sensor cannot see.

Decrypted data frames enter the normal flow, DNS, TLS and HTTP pipeline, so
the connection graph looks the same as for a wired capture. Open networks
need no keys.

**Keys survive restarts, and sync across sensors, through the server** — no
configuration needed. Pairwise keys live only in sensor memory, but when a
sensor installs one it ships the handshake's public nonces to the server,
which keeps the latest per client. Each key fetch returns them alongside
the PMKs, and the sensor re-derives the pairwise keys, so a restarted sensor
recovers its decryption coverage, and a second sensor decrypts clients whose
handshake another sensor caught. No key or MIC is ever sent by a sensor, and
nothing is written to the sensor's disk. The server stores only the
cleartext-broadcast nonces; the key file stays a file and is never copied
into the database.

If the interface is not in monitor mode, or no packets are 802.11, the
sensor treats it as Ethernet. Channel hopping is only started for interfaces
whose kernel link type is 802.11.

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
the same way: its token goes in `/etc/netgraph/server.token`, and the
database lives in `/var/lib/netgraph`. It also loads these optional files,
when present, and `netgraph serve` uses each without a flag: a read token in
`/etc/netgraph/read.token`, Wi-Fi keys in `/etc/netgraph/wifi.keys`, and a
certificate and key in `/etc/netgraph/tls.crt` and `/etc/netgraph/tls.key`.
Do not point flags in `server.conf` at `${CREDENTIALS_DIRECTORY}`: systemd
does not expand variables inside an `EnvironmentFile`.

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

### What a sidecar sees

A sidecar beside a server with published ports (a reverse proxy, say)
mostly sees connections *to* it: they are `in` connections, drawn as each
client's address pointing at the container (filter `dir:in`). Docker
forwards a published IPv4 port with NAT and keeps the client's address.
Some connections lose it on the way in:

- **IPv6 clients**, when the compose network has no IPv6: Docker's
  userland proxy (`docker-proxy`) accepts them on the host and opens a new
  IPv4 connection to the container from the bridge's gateway. The same
  goes for the host connecting to its own published port. All of these
  show as LAN connections from one device, the gateway (`172.18.0.1` or
  similar, often named after the host by reverse DNS), carrying every such
  client's TLS fingerprint and user agent. To see the real clients, give
  the network IPv6 (`enable_ipv6: true` and an IPv6 subnet on the network;
  Docker 27 and later NAT IPv6 with `ip6tables` and keep the client's
  address), or run the proxy and the sensor with `network_mode: host`.
- **Docker's DNS** answers on `127.0.0.11` inside the namespace, on `lo`,
  so a sidecar on `eth0` sees no lookups. The container's own outbound
  connections are still named by their TLS SNI or HTTP Host.
- **Loopback**: traffic between processes in the namespace (a proxy and
  a backend sharing it, the sensor shipping to a server there) never
  reaches `eth0`.

The capture interface's own MAC is the sensor's device, tagged `router`
and named after the sensor (`-name`).

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
