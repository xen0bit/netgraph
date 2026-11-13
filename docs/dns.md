# netgraph's DNS server

`netgraph serve -dns-listen :53` makes netgraph your network's DNS server, as
AdGuard Home or Pi-hole would be: it answers every lookup by asking upstream
resolvers, records each one (so the map, Activity → DNS and the anomaly checks
see every name, even ones a sensor can't), and refuses names you block.

It is off unless you start it. When it runs it is the second place netgraph acts
on traffic rather than only watching it (the other is the host agent's opt-in
firewall table), so it is bounded the same way:

- It answers only clients in `-dns-allow`: by default the private ranges,
  CGNAT, loopback and link-local. Anyone else gets `REFUSED`, at most 20 times a
  second, so it can't be used as an open resolver or to reflect traffic.
- It refuses only names an enabled blocklist or a rule you wrote names. There is
  no default blocking.
- It never touches a firewall, and nothing a model asks (Ask, MCP) can change
  its rules: those tools only read.

## Starting it

```sh
cat > /etc/netgraph/dns-upstreams <<'EOF'
# One a line. Encrypted upstreams keep your ISP out of your lookups.
tls://9.9.9.9#dns.quad9.net
https://cloudflare-dns.com/dns-query
udp://1.1.1.1
EOF
netgraph serve ... -dns-listen :53 -dns-upstream-file /etc/netgraph/dns-upstreams
```

Then point your DHCP server's DNS option (dnsmasq's `dhcp-option=6,<address>`,
your router's "DNS server" field) at the machine netgraph runs on.

| Flag | Default | |
|---|---|---|
| `-dns-listen` | off; `$NETGRAPH_DNS_LISTEN` | address for UDP and TCP, such as `:53` |
| `-dns-upstream-file` | `$NETGRAPH_DNS_UPSTREAM` | resolvers, one a line: `udp://`, `tcp://`, `tls://host#tls-name`, `https://` (DoH). Read from a file, not a flag: a DoH URL's path can hold an account's ID, and only the scheme and host are ever shown or logged |
| `-dns-allow` | private ranges | addresses or CIDRs that may ask |
| `-dns-block-mode` | `null` | a blocked name gets `0.0.0.0` and `::` (`null`), "no such name" (`nxdomain`) or `REFUSED` (`refused`) |

Upstreams are tried in order; one that fails is skipped for 30 seconds, unless
they all have. A host name in an upstream is resolved by the system's resolver:
if that will be netgraph itself, give an address, and the TLS name after `#`.
Port 53 needs `CAP_NET_BIND_SERVICE`; any port above 1023 doesn't. The packaged
systemd unit doesn't grant it unless asked, with a drop-in
(`systemctl edit netgraph`):

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

In Docker, where the image runs as a non-root user, listen on a high port inside
the container and publish 53 to it:

```yaml
    command: ["serve", "-db", "/data/netgraph.db", "-listen", ":8443",
              "-dns-listen", ":5353", "-dns-upstream-file", "/data/dns-upstreams",
              "-dns-allow", "192.168.0.0/16,172.16.0.0/12"]
    ports: ["8443:8443", "53:5353/udp", "53:5353/tcp"]
```

Docker's port publishing makes every client appear to come from the bridge's
gateway, so per-device rules can't tell clients apart there: `network_mode: host`
keeps their addresses. Don't publish it where the internet can reach it.

Answers are cached for their TTL, between 5 seconds and an hour, "no such name"
for the SOA's minimum (RFC 2308). UDP answers are at most 1232 bytes; a longer
one comes back truncated, and the client asks again over TCP. DNSSEC is passed
through, not validated.

## Blocking

Two things decide what's refused:

- **Blocklists** (Findings → Manage, or `netgraph blocklist`): hosts files,
  domain lists, and AdGuard/Adblock rules: `||ads.example^` blocks a name and its
  subdomains, `@@||ok.ads.example^` excepts one. A rule with modifiers
  (`$client`, `$dnsrewrite`) or wildcards means more than a name and is counted
  as invalid rather than guessed at. AdGuard's own DNS filter imports as it is.
- **Rules** (Settings → DNS server, the Block and Allow buttons on Activity →
  DNS, or `netgraph dns`): block or allow a name, and its subdomains, for
  everyone, one device (by MAC) or a group (Devices → a device's profile).
  `allow *` for a device turns filtering off for it.

The most specific say wins: a device's own rules, then its groups', then
everyone's, then the blocklists. Within one, allowing beats blocking. A name
that hides behind another (`tracker.example CNAME ads.cdn.example`) is refused
when the name it points to is.

Client addresses are matched to devices from what the sensors learned (ARP,
DHCP, NDP), refreshed every 30 seconds. An address no sensor has tied to a
device gets only the rules for everyone and the blocklists.

## What it records

Every lookup is a DNS event from the source `dns-server`, as a sensor's would
be: Activity → DNS, a device's lookups, names on the map. A refused one is
`BLOCKED`, and says what refused it (`rule 12`, `list AdGuard DNS filter`).
Answers name the connections that follow, as a sensor's sightings do.

A sensor that also sees a lookup sent to netgraph's own addresses would count it
twice; the server's copy is kept and the sensor's dropped.

`GET /api/v1/dns/stats` (and `netgraph dns stats`, and Home's "Lookups blocked"
card) counts lookups and refusals over a window, with the names most blocked
and asked for, and the busiest clients. It counts any source that reports
blocking, so an AdGuard Home or Pi-hole log (`-dns-log`) shows there too.

## CLI

```sh
netgraph dns rules
netgraph dns block ads.example.com
netgraph dns allow ads.example.com -device 02:11:22:33:44:55
netgraph dns allow '*' -device 02:11:22:33:44:55     # no filtering for this one
netgraph dns block games.example -group kids
netgraph dns delete 4
netgraph dns stats -from -24h
netgraph dns status -server https://netgraph.lan:8443
```

With `-db`, rules are written to the database, and a running server picks them
up within ten seconds; through `-server` it is at once.

## Erasure

Rules are configuration: `db purge` leaves them. `db forget` of a device
deletes the rules for its MAC. The lookups the server recorded are DNS rows like
any other, and follow retention, forget and purge.
