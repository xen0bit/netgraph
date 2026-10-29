# Concepts

## What the sensor records

The sensor turns packets into **events** and does no correlation of its
own:

| Event | From | Says |
|---|---|---|
| `flow` | every IP packet | one interval of one connection: bytes and packets each way, TCP flags, and once learned its TLS SNI/ALPN/JA4, QUIC SNI, HTTP Host/User-Agent |
| `dns` | DNS on port 53 (UDP and TCP) | a query, its answers with TTLs, the response code and latency; unanswered queries become `TIMEOUT` after 5 s |
| `binding` | ARP, NDP | this MAC uses this address |
| `dhcp` | DHCPv4, DHCPv6 | hostname, FQDN, vendor class, parameter-request list, client ID, leased addresses |
| `mdns` | mDNS/DNS-SD | `.local` hosts with their addresses, service instances with ports and TXT records |
| `name` | NBNS, LLMNR, reverse DNS | names a host claims or that its address resolves to |
| `ssdp` | SSDP | UPnP server strings, USNs, device types, description URLs |
| `lldp` | LLDP | a neighbour's system name, port and management address |
| `wifi` | monitor-mode 802.11 | access points, SSIDs, clients, associations and 4-way handshakes |
| `hello`, `stats` | the sensor | its interfaces (whose prefixes define "local") and counters |

TLS ClientHellos are reassembled from the first segments of a connection.
QUIC Initial packets (v1 and v2) are decrypted with the keys every client
derives from its own connection ID, and their CRYPTO frames are
reassembled even when they are split and reordered, as Chrome does. JA4
fingerprints match Wireshark's.

A connection reports an **interval record** every `-active-timeout` (30 s)
while it is open: the bytes of that interval, not running totals. A quiet
TCP connection still reports empty intervals, which is what lets netgraph
say it was open. A connection ends on FIN or RST, after an idle timeout,
or when the sensor stops.

Repeated announcements (mDNS, SSDP, LLDP, NetBIOS, Wi-Fi beacons and probe
requests) are reported once per 10 minutes per distinct content, and
bindings once per 5 minutes.

**Reverse DNS.** On live capture the sensor asks the system resolver for the
PTR name of a local address when it is first observed (an ARP/NDP binding, a
DHCP lease, mDNS address, DNS client or the local side of a flow). The
answer is emitted with the observation's timestamp, not the resolver's, so
a historical window shows the name the host had then. Answers are cached for
an hour and missing names for ten minutes. Replays do not do active lookups:
they must not depend on the resolver of the machine replaying them.

## What the server keeps

| Table | Holds | Kept |
|---|---|---|
| `entities` | devices (by MAC), addresses, DNS names, hostnames, services, fingerprints, user agents, UPnP descriptors, LLDP neighbours | while referenced |
| `facts` | relationships with the period they held: `device has_ip ip`, `device hostname h`, `domain resolves_to ip` (valid for the answer's TTL), `ip serves domain` (seen in SNI), ... | rollup retention (180 d) |
| `connections` | one row per connection: endpoints, device, names, totals, first and last seen | raw retention (14 d) |
| `flows` | the interval records | raw retention |
| `dns`, `dns_answers` | lookups and answers | raw retention |
| `observations` | identity events as received, for timelines | raw retention |
| `traffic_hourly`, `dns_hourly` | hourly rollups per device and destination | rollup retention |

A fact's rows are its **periods**. Seeing a relationship again within
`-fact-gap` (1 h) extends the current period; after a longer silence a new
period starts. So "which address did the laptop have at 14:00" has an
exact answer even when DHCP moved it at 13:30.

## Time windows

A window is half-open: `[from, to)`.

- **A connection is in the window** if any of its records overlaps it.
- **Its bytes in the window** are its records' bytes, with a record
  straddling an edge contributing the fraction of its interval inside.
  Slicing an hour into pieces gives back the hour's total.
- **Its state:** `carried` if it opened before `from` (the device *was*
  connected when the window began), `opened` if it opened inside the
  window, and `closed` if it ended (FIN, RST or idle) inside it.
- **Peak concurrency** is the largest number of connections open at one
  instant inside the window, overall and per graph edge.
- **A DNS answer is valid** from the moment it was received until its TTL
  runs out. A window sees `resolves_to` facts valid at any point in it,
  so an answer cached before the window still explains a connection made
  inside it.

**Freshness.** The server sees a connection's traffic when its interval
record arrives, at most `-active-timeout` plus the shipping interval
(about 30 s) after the fact. Lookups and identity events arrive within a
couple of seconds.

**Precision.** Windows older than raw retention, or longer than
`-exact-max`, are answered from hourly rollups: edges round to whole hours,
connection states are not available, and `precision` says `hour`.

## Correlation

**Which device.** The local end of a connection belongs to the MAC that
sent its packets. The sensor reports it per connection, so a device stays
correct when DHCP moves addresses around. Addresses are local if they are
in a private, link-local or CGNAT range, or in a prefix of a sensor's
capture interface (so a LAN with public IPv6 works). A host sending from
`0.0.0.0` before DHCP gives it an address is still attributed by its MAC.

**Which way.** A connection's direction says which end is here: `out` (a
device here opened it to something outside), `in` (something outside
opened it to a device here: a server, a forwarded or published port),
`local` (both ends) or `external` (neither, traffic passing through). Its
client is the end that opened it and its server the end that accepted it;
"port" always means the server's port. Bytes are counted from the device's
side whichever end opened the connection: a web server's responses are
what it sent.

**Which name.** A connection to an address is matched to the DNS lookup
that produced it, from answers that were valid when it opened (TTL plus a
10-minute grace, since clients cache past TTL). Many names share
addresses (CDNs, virtual hosting), so the order is: a lookup named by the
connection's own SNI or HTTP Host; then that client's most recent lookup;
then anyone's. The name shown for a connection is its SNI, else its HTTP
Host, else the DNS name.

**What a device is called**, in order of preference: its DHCP hostname,
DHCPv6 FQDN, mDNS name, NetBIOS name, LLMNR name, LLDP system name, the
sensor's name for the router itself, its reverse DNS name, and otherwise its
vendor and the end of its MAC (`Google aa:bb:cc`, `private 6c:1d:4e` for
randomised MACs). Reverse DNS is a fallback: a name the host or network
announced itself is always preferred.

**mDNS** records are credited to the device that holds their address, not
to whoever sent the packet: reflectors and sleep proxies answer for other
hosts. NetBIOS workgroup and browser-role names are not hostnames.

## The graph

Nodes are entities; edges aggregate the window. A `connects` edge always
points from the client to the server, the end that opened the connection
to the end that accepted it, and its label reads `443/tcp up 1.2MB down
68MB x12`: the server's port, what the client sent (up) and received
(down), and the number of connections.

```
device ──queried──▶ domain ──resolves_to (ttl)──▶ address
device ──connects (ports, bytes, carried/opened/closed, peak)──▶ domain
device ──connects──▶ address        (when no name is known)
device ──connects──▶ device         (LAN to LAN)
address ──connects──▶ device        (a client outside reaching a server here)
domain ──cname──▶ domain
device ──hostname / announces / fingerprint / user_agent / upnp / neighbor / vendor──▶ ...   (with Identity)
device ──broadcasts / probes / associates / handshake──▶ ssid or device   (Wi-Fi, with Identity)
```

With **collapse** (default), a destination reached by name is one node
listing its addresses, rather than a node per CDN address. With **sites**
(default), names are grouped by registrable domain under the ICANN public
suffixes: one `time.com` node for www.time.com, auth.time.com and the rest,
one `cloudfront.net` for its distributions. A site of one name reads as
that name. **Top N** keeps each device's busiest destinations (sites, with
sites on) and draws the rest as one "N more destinations" node, with their
traffic, and marks the graph truncated.

**Connections from outside.** A server here (port forwarding, a published
container port, a reverse proxy) accepts connections from the internet.
Each client is drawn by its address with an edge into the device, labelled
with the device's port and the name the client asked for (`for
www.example.com`): the name is the server's own, so it is not drawn as a
destination. Top N keeps a device's busiest clients apart from its
destinations, so a web server's visitors do not crowd out where it
connects itself; the rest are one "N more clients" node. The device's node
lists the ports it served (`serves 443/tcp, 80/tcp`). A client's TLS
fingerprint and user agent describe the client: they are facts about its
address, not the device's identity.

**Networks.** When the server has an [ASN
table](deployment.md#networks-and-countries), each connection records the
network (autonomous system) and country of its remote end at ingest. With
**networks** (default), an address whose network is known is drawn as its
network: one `AS24940 HETZNER-AS` node (`DE · 14 addresses`) for a server's
visitors from that provider, and likewise for destinations reached without
a name. Named destinations stay names. Top N then ranks networks, so many
small visitors from one provider can outrank one large one. Without the
option, an address node is labelled with its network.

Each relationship is drawn once, so a busy window stays readable:

- A device that looked a name up and connected to it has one `connects`
  edge, with the lookups counted on it (`dns x3`). A lookup that led to no
  connection (`NXDOMAIN`, a prefetch) keeps its own dashed edge.
- A CNAME chain is folded into the name it started from: `via
  fastly.net` on the node, not a node per CDN alias. A target the graph
  draws anyway keeps its `cname` edge. Without collapse, chains are drawn
  as they are.
- With identity, services, UPnP and LLDP descriptions and Wi-Fi networks
  are nodes; hostnames, addresses, fingerprints, user agents and vendors
  are nodes only when two or more devices share them, which is when they
  say something (the same JA4 on two devices; two devices claiming one
  address). One device's own are on its node and in its details.
- A device with eight or more destinations that only it reaches, and that
  nothing else in the graph touches, draws them as a grid, busiest first,
  with one edge carrying their totals; each keeps its ports and connection
  count on its label. Eight or more such clients are a grid too, with its
  edge into the device.

## Anomalies

The server checks each window for what stands out, and says why. Every
finding names the device, what it is about, and the numbers behind it; a
rule that fired can always be explained from its evidence. Findings are
listed most severe first (`GET /api/v1/anomalies`, the **Anomalies** tab,
`netgraph query anomalies`), and with the graph's **anomalies** option
(default on) medium and high ones outline their device, destination and the
edge between them, red for high and orange for medium, with the reasons as
a tooltip. Low ones stay in the list.

Checks that need no history:

| Kind | Fires when | Severity |
|---|---|---|
| `beacon` | a device opens connections to one destination on a fixed period: at least 8, at least 10 s apart, gaps within 10% (median) of each other. Starts within a second count once; DNS, NTP and mDNS are left out | low to a name, medium to an unnamed address |
| `dns_failures` | a device looks up at least 20 names that do not exist, 30% or more of its names (malware generating domains, or a broken device). Single labels, reverse lookups and local suffixes do not count | medium, high from 100 |
| `dns_tunnel` | a device looks up at least 50 different names under one site whose first labels are 20 characters or more (median): data smuggled out in the names | medium, high from 500 |
| `rogue_ap` | access points broadcast one network name with different security | high when one is open or WEP and another protected (an evil twin); low otherwise (WPA2 next to WPA3 is common on mesh and 6 GHz radios) |
| `scan` | an address outside tries at least 10 ports on a device, most of them probes that never became a session (refused, unanswered, or half-open); or one port on at least 10 addresses here | low: a server on the internet is scanned all day. More than 10 scanners of one device are one finding, with the networks most of them came from |
| `brute_force` | an address outside opens at least 50 short sessions (under 10 s) to a login service on a device: SSH, Telnet, FTP, RDP, VNC, mail, databases. Web logins look like any page load, so they are not counted | medium, high from 500; low for 500 or more from at least 20 addresses with fewer each |

Checks that compare with history need a day of it: until the first sensor
has reported for 24 hours the report says `learning` and they are skipped,
since everything is new to a network just met. They look back 7 days.

| Kind | Fires when | Severity |
|---|---|---|
| `new_device` | a device uses an address on the LAN for the first time (the same event as a [new-device alert](deployment.md#new-device-alerts); not the router, not devices only heard over the air) | medium; low for a private (randomised) MAC, which phones rotate |
| `new_destination` | a device with a day of history connects to a site, or an unnamed address, it had not in the last 7 days. A device that reached at most 30 destinations that week is predictable (a plug, a camera) and anything new from it counts; from a busier one only a new destination it uploaded 1 MB or more to | medium from a predictable device, high if also new to the whole network with 10 MB up; low from a busy one, medium if new to the network with 50 MB up. More than 10 for one device are summed up in one |
| `upload_spike` | a device sends more per hour, on connections it opened, than in any hour of its last week, at least 4 times its median hour and at least 20 MB an hour. It needs 24 active hours of history | medium; high at 5 times its busiest hour and 200 MB an hour |
| `rogue_ap` | a new access point broadcasts a network that the LAN's own devices (ones that used an address on it) associate with | medium |
| `new_service` | a device holds sessions with clients outside on a port it had not served in the last 7 days, with at least 3 clients or 1 MB: a newly forwarded port or a container published by mistake. Dynamic ports (49152 and up), which peer-to-peer apps open, do not count | medium |
| `inbound_surge` | a device accepts more connections from outside in an hour than 4 times its busiest hour of the last 7 days, and at least 1000. It needs 24 active hours of history | medium; high at 10 times and 10,000 an hour |

The checks for servers here look only at connections opened from outside
(direction `in`): traffic between devices here, such as a reverse proxy's
loopback, never counts. A probe is a connection in which the client sent
at most 3 packets and the device at most 2; a session is one the device
answered with 3 or more. With an [ASN table](deployment.md#networks-and-countries),
findings name each source's network and country.

A window shorter than an hour is compared with hours as it is: its total
is a lower bound on that hour's. A device filter keeps that device's
findings; other filters do not apply.

## Wi-Fi

A sensor capturing a monitor-mode interface receives radiotap frames. It
records access points (by BSSID, as devices with role `access_point`), the
SSIDs they broadcast, probe requests, associations and 4-way handshakes.
The graph can show `access point ──broadcasts──▶ SSID`,
`device ──probes/associates──▶ SSID/access point`, and handshake edges with
the message number and cipher.

**Decryption** happens on the sensor, before events are shipped, with keys
the sensor fetches from the server and holds only in memory:

- **Open** networks are passed through.
- **WEP** uses the configured 40/104/128-bit shared keys.
- **WPA/WPA2-PSK** uses the PMK the server derived from the SSID and
  passphrase in its key file (PBKDF2), or a raw PMK. It follows EAPOL
  messages 1–4, derives the PTK from the nonces, verifies the MIC, and
  decrypts CCMP or TKIP data frames.
- **WPA3/SAE, OWE and 802.1X** cannot be followed from the air alone. They
  are parsed and reported as networks, and can be decrypted only when a PMK
  is supplied (`pmk <ssid> <hex>` in the server's key file).

Decrypted data frames are rebuilt as Ethernet and enter the normal flow,
DNS, TLS and HTTP pipeline, so a Wi-Fi capture produces the same connection
graph as a bridge capture. A-MSDU aggregates (common with 802.11n/ac/ax
clients) are split into their subframes. The AP's **group key** (GTK),
which encrypts its broadcasts and multicasts, is unwrapped from handshake
message 3 or a later group rekey to any client whose pairwise key the
sensor holds, so the mDNS, SSDP and DHCP broadcasts that name devices are
decoded too. A broadcast the AP relays from a client the sensor already
decrypts is skipped rather than counted twice. Keys flow one way, server to
sensor: the server keeps the passphrases in its key file and serves only
the derived PMKs and WEP keys, over the ingest-token endpoint. No key leaves
the sensor — not the PMK, PTK, GTK or MIC — and the sensor writes
nothing to disk; `wifi` events carry only public facts (BSSID, SSID, client,
channel, security, cipher, handshake message number and whether its MIC
verified).

**Handshake persistence and sync.** Pairwise keys live only in sensor
memory, so a sensor restart would otherwise lose them until each client
re-associated. To avoid that, a sensor that installs a key ships a
`wifi_key` event carrying just the handshake's two **nonces** — values the
AP and client broadcast in the clear, so not secret. The server keeps the
latest per `(AP, client)` in `wifi_handshakes`, and a sensor fetches them
with its PMKs on startup (and every minute) to re-derive the PTK. The same
mechanism lets several sensors share keys: one sensor catches a client's
handshake, the rest decrypt that client too.

Group keys sync the same way. When a sensor learns an AP's GTK it ships a
`wifi_gtk` event with the GTK **as the AP sent it — still wrapped with the
client's KEK** — and the nonces of that client's handshake. The server keeps
the latest per `(AP, key ID)` in `wifi_group_keys`. Another sensor
re-derives the client's KEK from its own PMK and the nonces, unwraps the
GTK, and decrypts the AP's broadcasts straight away instead of waiting for
the next rekey. A record older than the key a sensor already holds in that
slot is ignored.

Neither table holds a usable key: the nonces are public and the GTK is
ciphertext. Both decrypt something only with the network's PMK, which the
server derives from its key file and never stores in the database. A
sensor only ships these for a network whose PMK it holds, so the tables only
ever cover your own networks.

Channel hopping is available with `-wifi-hop`. It uses the wireless
extensions ioctl, so it works with mac80211 monitor interfaces and not with
6 GHz-only devices; a fixed channel is always an option.

## Blind spots

- **Encrypted Client Hello** hides the real SNI (the outer, public name is
  seen instead). DNS correlation still names most such connections.
- **DNS over HTTPS / TLS / QUIC** hides lookups: you see a connection to
  the resolver, and other connections go unnamed unless they carry an SNI.
  Point clients at the router's resolver to keep names.
- **Hardware flow offloading** hides established connections' packets
  from the CPU (see [deployment](deployment.md#where-to-capture)).
- **Switch-local traffic** never reaches the router.
- **VPNs and tunnels** show as one connection to the tunnel endpoint.
- **Randomised MACs** make a phone a new device on each network or after
  a reset. Its DHCP hostname often still names it.
- **IPv4 fragments** after the first are not counted.
- **DNS over TCP** is decoded only when a whole message fits in one
  segment, which covers ordinary lookups but not zone transfers.
- **WPA3/SAE, OWE and 802.1X** Wi-Fi has no passively derivable PMK; without
  an explicitly supplied PMK, their data frames stay encrypted.
- **Wi-Fi group keys** come from a message 3 or group rekey that some
  sensor saw. A network whose GTK no sensor has seen since netgraph started
  (no client joined and the AP has not rekeyed) keeps its broadcasts
  encrypted until one does. GCMP ciphers (some WPA3 suites) are not
  implemented yet; CCMP and TKIP are.
- **Fragmented 802.11 frames** are not reassembled; those data frames are
  counted but not decoded. (Fragmentation is rare on modern networks.)
- **Wi-Fi on other channels** is missed while the monitor interface is
  hopping. A busy network also loses frames during the hop itself.
