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

Nodes are entities; edges aggregate the window:

```
device ──queried──▶ domain ──resolves_to (ttl)──▶ address
device ──connects (ports, bytes, carried/opened/closed, peak)──▶ domain
device ──connects──▶ address        (when no name is known)
device ──connects──▶ device         (LAN to LAN)
domain ──cname──▶ domain
device ──hostname / announces / fingerprint / user_agent / upnp / neighbor / vendor──▶ ...   (with Identity)
device ──broadcasts / probes / associates / handshake──▶ ssid or device   (Wi-Fi, with Identity)
```

With **collapse** (default), a destination reached by name is one node
listing its addresses, rather than a node per CDN address. **Top N** keeps
each device's busiest destinations and marks the graph truncated.

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
graph as a bridge capture. Only pairwise keys are followed; group/broadcast
keys are not derived, so multicast Wi-Fi data stays encrypted. Keys flow one
way, server to sensor: the server keeps the passphrases in its key file and
serves only the derived PMKs and WEP keys, over the ingest-token endpoint.
No key leaves the sensor — not the PMK, PTK or MIC — and the sensor writes
nothing to disk; `wifi` events carry only public facts (BSSID, SSID, client,
channel, security, cipher, handshake message number and whether its MIC
verified).

**Handshake persistence and sync.** Pairwise keys live only in sensor
memory, so a sensor restart would otherwise lose them until each client
re-associated. To avoid that, a sensor that installs a key ships a
`wifi_key` event carrying just the handshake's two **nonces** — values the
AP and client broadcast in the clear, so not secret. The server keeps the
latest per `(AP, client)` in `wifi_handshakes`, and a sensor fetches them
with its PMKs on startup (and every minute) to re-derive the PTK. The same mechanism lets several sensors share keys: one sensor catches
a client's handshake, the rest decrypt that client too. The server stores
no raw frames and never copies the key file into the database, so the stored
nonces decrypt nothing on their own. A sensor only ships a `wifi_key` for a
network whose PMK it holds, so the table only ever covers your own networks.

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
- **Wi-Fi group keys** (broadcast/multicast) are not derived, even when the
  pairwise handshake was captured. GCMP ciphers (some WPA3 suites) are also
  not implemented yet; CCMP and TKIP are.
- **Wi-Fi aggregates and fragments** (A-MSDU, fragmented 802.11 frames) are
  not reassembled yet; those data frames are counted but not decoded.
- **Wi-Fi on other channels** is missed while the monitor interface is
  hopping. A busy network also loses frames during the hop itself.
