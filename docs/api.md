# HTTP API

All query endpoints are `GET`, return JSON, and take the window and
filter as parameters. When the server has a read token, send it as
`Authorization: Bearer <token>` (or `?token=` for the live stream).
Times in responses are unix milliseconds.

## Window and filter parameters

| Parameter | |
|---|---|
| `from`, `to` | unix ms, RFC 3339, local `2026-10-25 14:00`, or relative `-1h`; default the last hour |
| `device` | MAC, label or hostname glob |
| `ip` | address or CIDR |
| `domain` | DNS name / SNI / HTTP host glob |
| `port`, `proto`, `app` | the server's port (the service, whichever end is the device), `tcp`/`udp`/number, application |
| `dir` | `out` (a device here connected out), `in` (opened from outside to a device here), `local` or `external` |
| `asn`, `cc` | the remote end's network (`13335` or `AS13335`) and country (`DE`), from the server's [ASN table](deployment.md#networks-and-countries) |
| `multicast` | `1` to include multicast and broadcast |
| `limit` | maximum rows |

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /api/v1/summary` | `{devices, flows, inbound, peak_connections, dns_queries, domains, remote_ips, bytes_out, bytes_in, precision, ...}`; bytes are what devices here sent and received |
| `GET /api/v1/devices` | `[{id, mac, label, user_label, auto_label, vendor, vendor_short, randomized, role, ips, hostnames, services, serves, fingerprints, user_agents, flows, inbound, dns_queries, bytes_out, bytes_in, remotes, active_from, active_to, first_seen, last_seen}]`; `serves` lists the ports clients connected to (`443/tcp`), `inbound` how many connections came in from outside |
| `GET /api/v1/flows` | `[{key, proto, client_ip, client_port, server_ip, server_port, device, device_name, device_mac, remote_ip, remote_port, peer_device, peer_name, direction, app, name, sni, http_host, qname, alpn, ja4, user_agent, asn, as_org, country, first_seen, last_seen, state, closed, end_reason, bytes_out, bytes_in, pkts_out, pkts_in}]`, busiest first (see [Flows](#flows)) |
| `GET /api/v1/dns` | `[{ts, client_ip, device, device_name, server, qname, qtype, rcode, latency_ms, answers: [{name, type, data, ttl, expires}]}]`, newest first |
| `GET /api/v1/facts` | `[{rel, src, src_label, dst, dst_label, first_seen, last_seen, count, source, attrs}]` |
| `GET /api/v1/timeseries?step=5m` | `{step, precision, buckets: [{ts, bytes_out, bytes_in, flows_new, dns_queries, devices}]}` |
| `GET /api/v1/graph` | `{from, to, precision, truncated, nodes: [{id, kind, label, sub, local, bytes_out, bytes_in, attrs}], edges: [{from, to, rel, count, bytes_out, bytes_in, carried, opened, closed, peak, ports, ttl, first_seen, last_seen, attrs}]}` |
| `GET /api/v1/graph?format=svg\|d2\|txt` | the graph drawn by the server; `theme=dark`, `layout=elk\|dagre` |
| `GET /api/v1/entity?id=device:3c:22:fb:01:02:03` | `{id, kind, key, label, attrs, device, facts, flows, dns, timeline: [{ts, type, detail}]}` |
| `GET /api/v1/sensors` | `[{name, version, interfaces, first_seen, last_seen, stats}]` |
| `GET /api/v1/wifi` | `[{bssid, ssid, security, channel, clients, first_seen, last_seen}]`, from monitor-mode sensors |
| `GET /api/v1/live` | server-sent events: `event: ingest` with `[{type, ts, detail}]` per batch |
| `PUT /api/v1/devices/{mac}/label` | names a device by hand: body `{"label": "Living room TV"}` (JSON required; at most 64 printable characters), `{"label": ""}` restores the automatic name. `204`, or `400`/`404`. Read token |
| `GET /api/v1/anomalies` | the window's [anomalies](concepts.md#anomalies), most severe first: `{from, to, since, learning, anomalies: [{kind, severity, ts, device, device_name, entity, summary, evidence}]}`. Read token |
| `GET /metrics` | Prometheus text: ingest counters, each sensor's last reported stats (packets, kernel drops, queued and dropped events, ...), entities by kind, database size, alert outcomes. Read token |
| `GET /api/v1/version`, `/healthz` | `{version, commit}`; no token needed |

Graph options: `collapse=0|1` (default 1), `dns=0|1` (1), `sites=0|1` (1),
`anomalies=0|1` (1; outline what medium and high anomalies are about),
`networks=0|1` (1; one `asn:<number>` node per network for clients from
outside and unnamed destinations, when the server has an ASN table),
`identity=0|1` (0), `top=N` (15; `-1` for all). `GET /api/v1/entity` also
answers for a graph's `site:<registrable domain>` nodes: the connections,
lookups and facts of every name under it, and for `asn:<number>` (a
network's connections in the window).

```sh
curl -s -H "Authorization: Bearer $NETGRAPH_READ_TOKEN" \
  "http://netgraph.lan:8443/api/v1/flows?from=-1h&device=alice-*&app=quic" | jq .
```

### Flows

A flow is one connection. `client_*` is the end that opened it and
`server_*` the end that accepted it. `device` is the device here it belongs
to, and `remote_*` the other end: the server, unless `direction` is `in`
(someone outside connected to a server here), when it is the client.
`bytes_out`/`pkts_out` are what the device sent, `bytes_in`/`pkts_in` what
it received, whichever end opened the connection. For an inbound
connection, `name` is the name the client asked for (its SNI or Host),
which is the device's own; its `ja4` and `user_agent` are the client's, and
are recorded as facts about the client's address. `peer_device` and
`peer_name` name the server when it is a device here too. Rows from hourly
rollups keep only the server's port. `asn`, `as_org` and `country` describe
the remote end's network when the server has an ASN table; they are absent
for local ends and addresses no network announces.

In graphs, every `connects` edge points from client to server, and its
`bytes_out` is what the client sent (the edge's "up"). An inbound client is
an `ip:` node with an edge into the device; Top N keeps each device's
busiest `top` destinations and, separately, its busiest `top` clients, and
the rest of each become `other:<device>` ("N more destinations") and
`other:clients:<device>` ("N more clients"). A device node's `serves` and
`served_names` attributes list the ports and names clients asked it for.

## Ingest

Sensors `POST /api/v1/ingest` with:

| Header | |
|---|---|
| `Authorization: Bearer <ingest token>` | |
| `X-Netgraph-Sensor` | sensor name |
| `X-Netgraph-Boot` | random per sensor start; scopes sequence numbers |
| `X-Netgraph-Version` | event schema version (`1`) |
| `Content-Encoding: zstd` | optional; plain JSON lines are accepted too |

The body is newline-delimited JSON events, each `{seq, type, ts, <type>:
{...}}`, as defined in [`internal/wire/event.go`](../internal/wire/event.go).
Event types are `hello`, `stats`, `flow`, `dns`, `binding`, `dhcp`, `mdns`,
`name`, `ssdp`, `lldp`, `wifi`, `wifi_key` and `wifi_gtk`. A `name` from
reverse DNS has `"proto":"rdns"`; a `wifi` event describes an access point,
client, association or handshake and never carries key material. A
`wifi_key` event carries a handshake's public nonces, and a `wifi_gtk` event
an AP's group key still wrapped with a client's KEK, so keys survive a
sensor restart and sync across sensors (see [Wi-Fi keys](#wi-fi-keys));
neither holds a usable key. Events with a
`seq` at or below the last one ingested for that sensor boot are skipped, so
retries are safe. The response is `{accepted, duplicates}`. Anything that
can produce these events can feed netgraph:

```sh
netgraph-sensor run -pcap capture.pcap -server - > events.jsonl   # JSON lines on stdout
curl -X POST -H "Authorization: Bearer $NETGRAPH_TOKEN" -H "X-Netgraph-Sensor: test" \
  --data-binary @events.jsonl http://netgraph.lan:8443/api/v1/ingest
```

### Wi-Fi keys

`GET /api/v1/wifi/keys` returns what a sensor needs to decrypt Wi-Fi. It is
authorised with the **ingest** token (it is sensor infrastructure), and
sensors call it automatically on startup and every minute. The response is
`{pmks, wep, handshakes, group_keys}`:

- `pmks`: `[{ssid, pmk}]`, the 32-byte PMK (hex) for each network in the
  server's `-wifi-key-file`. Passphrases are not sent; the server derives
  the PMKs.
- `wep`: `[{index, key}]`, the configured WEP keys (hex).
- `handshakes`: `[{bssid, sta, ssid, anonce, snonce, key_version}]`, the
  latest stored 4-way handshake nonces per client, from `wifi_key` events.
  These are broadcast in the clear and decrypt nothing on their own; with a
  network's PMK they let a restarted or additional sensor re-derive the
  pairwise key without seeing the handshake again.

- `group_keys`: `[{bssid, sta, ssid, key_id, anonce, snonce, descriptor,
  key_info, key_length, iv, key_data, ts}]`, the latest group key per AP and
  key ID from `wifi_gtk` events: the EAPOL-Key fields with `key_data` still
  wrapped by the client's KEK. A sensor re-derives that KEK from the PMK and
  the nonces and unwraps the GTK, so it decrypts the AP's broadcasts
  without waiting for a rekey.

`pmks` and `wep` are empty unless the server has a key file **and** an
ingest token; a server started with `-no-auth` never serves keys.
