# HTTP API

All query endpoints are `GET`, return JSON, and take the window and
filter as parameters. When the server has a read token, send it as
`Authorization: Bearer <token>`. The live stream also accepts `?token=` for
clients like `EventSource` that cannot set headers; the web UI does not use
it. Query tokens elsewhere are rejected, since they leak into logs and Referer
headers. Responses larger than a few bytes are gzip-compressed when the
client accepts it; the live stream is not compressed. Times in responses
are unix milliseconds.

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
| `offset` | rows to skip, for paging (`limit` + `offset`) |

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /api/v1/map/pins` | `[{id, x, y, updated}]`: nodes a person placed on the map. `PUT` with `{"pins": [{id, x, y}]}` places them, `DELETE` with `{"ids": [...]}` removes them (JSON required; `204`). IDs are graph node IDs. Read token |
| `GET /api/v1/range` | `{first_ms, last_ms, raw_from_ms, rollup_from_ms, now_ms}`: the span of the data held (zeros when there is none) and where each retention tier begins. Takes no window |
| `GET /api/v1/home?since=<ms>` | `{state, now, as_of, since, since_clamped, sensors: [{name, version, last_seen, interfaces, quiet}], active, new_devices, top_talkers, summary_since, traffic}`: the landing page. `state` is `ok`, `quiet` (no sensor has reported for 2 minutes), `imported` (data, no sensor) or `no_data`. `as_of` is the newest data held, and everything is answered as of it. `active` were seen in the 10 minutes before it, `top_talkers` are the busiest 5 in the hour before it, `new_devices` were first seen since `since` (default a day, at most 7, then `since_clamped`). Takes no window or filters |
| `GET /api/v1/passport?id=device:<mac>&tz=<minutes>` | `{id, as_of, week_from, last_week_from, device, hours, days, this_week, last_week, has_last_week, new_destinations, destinations, story}`: a device's profile from the hourly rollups. `tz` is the reader's offset from UTC, east positive, for `hours` (24 byte counts this week) and `days`. A destination is `new` if absent the week before, and only when the device existed then (`has_last_week`). `story` is the last 24 hours. Takes no window or filters |
| `GET /api/v1/presence` | `{from, to, precision, gap, devices: [{id, label, type, owner, intervals: [[from, to], ...]}]}`: when each device moved traffic, from per-minute totals, or hourly past their retention. Silence under `gap` ms doesn't split an interval. Takes the window and `device` |
| `GET /api/v1/devices/links` | `[{device, same, confidence, reasons: [{signal, value}]}]`: private MACs that look like a known device |
| `POST /api/v1/devices/{mac}/link` | `{"same": "<mac>", "decision": "same"\|"different"\|"undo"}`: answers a suggestion (`204`). JSON required. Operator |
| `PUT /api/v1/devices/{mac}/profile` | `{"type": "printer", "owner": "Alice", "groups": ["iot"]}`: what a person says about a device; a field left out is unchanged, empty clears it (`204`). JSON required. Operator |
| `GET /api/v1/findings?status=open&since=<ms>&to=<ms>&device=<id>&limit=` | `{findings, groups: [{device, device_name, from, to, severity, ids}], counts, scanned_at, learning}`: findings with memory, newest first. `status` is `new`, `seen`, `acknowledged`, `resolved`, `dismissed`, or `open` for the first three. `counts` covers every finding by status. A finding is an anomaly plus `{id, first_seen, last_seen, occurrences, status, status_at, auto_resolved, recurrences, note}` |
| `GET /api/v1/findings/{id}` | One finding, also with `why`, `advice` and `usual` |
| `PATCH /api/v1/findings/{id}` | `{"status": "new"\|"seen"\|"acknowledged"\|"resolved", "note": "..."}` (`204`). JSON required. Operator |
| `POST /api/v1/findings/{id}/fine` | `{"note": "..."}`: dismisses it and mutes its kind, device and entity with no practical end (`204`). JSON required. Operator |
| `POST /api/v1/findings/seen` | Marks every new finding seen (`204`). JSON required. Operator |
| `GET /api/v1/notify` | `{channels: [{name, min, kinds, quiet}]}`: where alerts go, with no secrets |
| `POST /api/v1/notify/test` | `{"name": "..."}`: sends a test, past filters and quiet hours. `{ok, error}`, or `404` for no such channel. JSON required. Admin |
| `GET /api/v1/ask/config` | `{llm: {model, host, local}}`, or `{}` with none configured. `POST /api/v1/ask` with `"llm": true` uses it (`400` if none, `429` if busy, `502` if it fails). The answer has `model` set, and citations of kind `tool` |
| `GET /api/v1/me` | `{user, role, via}`: who this request is from. `role` is `viewer`, `operator` or `admin`; `via` is `proxy`, `token`, `session` or `open` |
| `POST /api/v1/session` | `{"token": "..."}`: sets a session cookie (`HttpOnly`, `SameSite=Strict`) for that token's role. `DELETE` clears it (`204`) |
| `GET /api/v1/audit?limit=` | `[{id, ts, actor, role, action, target, remote}]`, newest first. Admin |
| `GET /api/v1/quality` | `{from, to, step, verdict, summary, wan, lan, usual, dns, dns_queries, dns_timeouts, retrans_pct, unanswered, outages: [{from, to, attempts}], series: [{ts, wan_p50_ms, lan_p50_ms, retrans_pct}], devices: [{id, label, wan, lan, retrans_pct}], gaps}`: delay and loss, from TCP handshakes, retransmits and DNS. Each path is `{p50_ms, p95_ms, samples}`. `verdict` is `good`, `unknown`, `slow_local`, `slow_upstream`, `lossy` or `outage`. Takes the window (at most 7 days) and `device` |
| `GET /api/v1/summary` | `{devices, flows, inbound, peak_connections, dns_queries, domains, remote_ips, bytes_out, bytes_in, precision, ...}`; bytes are what devices here sent and received |
| `GET /api/v1/devices` | `[{id, mac, label, user_label, auto_label, vendor, vendor_short, randomized, role, ips, hostnames, services, serves, fingerprints, user_agents, flows, inbound, dns_queries, bytes_out, bytes_in, remotes, active_from, active_to, first_seen, last_seen, type, type_confidence, user_type, owner, groups, same_as}]`; `device=` also takes `type:printer`, `owner:alice` or `group:iot`; `serves` lists the ports clients connected to (`443/tcp`), `inbound` how many connections came in from outside |
| `GET /api/v1/destinations` | `[{key, kind, label, connections, devices, bytes_out, bytes_in, first_seen, last_seen, ports, remote_ips}]`: remote ends aggregated by name, or by address when no name is known, busiest first. One name with several addresses is one row; `ports` is `443/tcp` style and `remote_ips` lists the addresses. Uses the window and filters. |
| `GET /api/v1/flows` | `[{key, proto, client_ip, client_port, server_ip, server_port, device, device_name, device_mac, remote_ip, remote_port, peer_device, peer_name, direction, app, name, sni, http_host, qname, alpn, ja4, user_agent, asn, as_org, country, first_seen, last_seen, state, closed, end_reason, bytes_out, bytes_in, pkts_out, pkts_in, connections}]`, busiest first (see [Flows](#flows)). `sort=first_seen`, `last_seen`, `bytes`, `bytes_out` or `bytes_in`, with `-` in front for descending, orders them before the limit; hourly answers ignore it |
| `GET /api/v1/dns` | `[{ts, client_ip, device, device_name, server, qname, qtype, rcode, latency_ms, count, answers: [{name, type, data, ttl, expires}]}]`, newest first; `count` is set on hourly rollup rows |
| `GET /api/v1/facts` | `[{rel, src, src_label, dst, dst_label, first_seen, last_seen, count, source, attrs}]`; facts support the window and the `device`, `domain` and `ip` filters only |
| `GET /api/v1/timeseries?step=5m` | `{step, precision, buckets: [{ts, bytes_out, bytes_in, flows_new, dns_queries, devices}]}` |
| `GET /api/v1/graph` | `{from, to, precision, truncated, nodes: [{id, kind, label, sub, local, bytes_out, bytes_in, attrs}], edges: [{from, to, rel, count, bytes_out, bytes_in, carried, opened, closed, peak, ports, ttl, first_seen, last_seen, attrs}]}` |
| `GET /api/v1/graph?format=svg\|d2\|txt` | the graph drawn by the server; `theme=dark`, `layout=elk\|dagre` |
| `GET /api/v1/entity?id=device:3c:22:fb:01:02:03` | `{id, kind, key, label, attrs, device, facts, flows, dns, timeline: [{ts, type, detail}]}` |
| `GET /api/v1/entity?id=sensor:router` | a sensor's version, interfaces and last reported counters (`attrs`), so `sensor_silent` and the Sensors table can open one |
| `POST /api/v1/whatif` | `{policy, from, to}`: what a policy would have done to the window's traffic. Viewer |
| `GET /api/v1/policy/learn?device=device:MAC&from=-14d` | `{device, from, to, connections, policy, gaps}`: the least a device needs, from what it did. Saves nothing. Viewer |
| `POST /api/v1/policy/export` | `{policy, format, from, to}`, with `format` as `nftables`, `openwrt` or `opnsense`: `{format, filename, config, warnings}`. Changes nothing. Viewer |
| `GET/POST /api/v1/policies` | list or create saved policies. `GET` returns `[{id,name,version,mode,active,rules,notes,created,modified}]`; `POST` takes a policy JSON. Operator for writes |
| `GET/PUT/DELETE /api/v1/policies/{id}` | load, replace or delete one policy |
| `POST /api/v1/policies/{id}/activate` | make one policy active (`204`). Operator |
| `GET /api/v1/policies/active` | the active policy, or `404` |
| `POST /api/v1/policy/explain` | `{policy}` or `{id}` plus `{conn}`: the winning decision and every other matching rule |
| `GET /api/v1/policy/audit?id=` | conservative audit: redundant/shadowed/contradictory/invalid/blocklist-override findings |
| `GET /api/v1/blocklists` | configured blocklists and entry counts |
| `POST /api/v1/blocklists` | create a blocklist: `{name,url,format,enabled}`. Operator |
| `GET/PUT/DELETE /api/v1/blocklists/{id}` | load, update (name, URL, format, group, enabled, interval; fetch state and counts are kept) or delete one blocklist |
| `GET /api/v1/blocklists/{id}/entries` | parsed entries; `enabled=1` for only enabled rows |
| `PATCH /api/v1/blocklists/{id}/entries/{entry}` | `{enabled}` (`204`). Operator |
| `POST /api/v1/blocklists/{id}/import` | `{text,format}`: parse and replace entries. Operator |
| `POST /api/v1/blocklists/{id}/update` | fetch the URL now, over HTTPS to a public address only. Operator |
| `GET/POST /api/v1/rule-groups` | blocklist groups |
| `GET/POST /api/v1/profiles` | policy profiles; writes are Operator |
| `GET/PUT/DELETE /api/v1/profiles/{id}` | load, replace or delete one profile |
| `POST /api/v1/profiles/{id}/activate` | activate a profile (`204`) |
| `POST /api/v1/profiles/evaluate` | apply the first matching network trigger and return the active profile |
| `GET /api/v1/network` | the current network signature: `{signature,ssid,bssid,router,interface}`; triggers are globs over `signature` |
| `GET/POST /api/v1/network-triggers` | list or create triggers; `DELETE /network-triggers/{id}` removes one |
| `GET /api/v1/decisions?status=open` | policy decisions, newest first |
| `GET /api/v1/decisions/{id}` | one decision plus a `prefilled_rule` |
| `POST /api/v1/decisions/scan` | `{from,to,limit}`: record would-ask decisions for a window |
| `POST /api/v1/decisions/{id}/allow\|deny` | record an answer once, `{note}`; returns the decision. Operator |
| `POST /api/v1/decisions/{id}/rule` | `{action: allow\|deny, note}`: add a rule for this device and destination to the active version 2 policy; returns the decision with its `rule_id`. Operator |
| `POST /api/v1/decisions/{id}/reset` | reopen a decision. Operator |
| `POST /api/v1/decisions/expire` | `{before}`: expire old open decisions |
| `GET /api/v1/connections?group=device\|app\|domain\|host\|destination\|remote` | connections folded into monitor groups |
| `GET /api/v1/geo?ip=` | local geo table lookup; `GET /api/v1/geo/status` says whether one is loaded |
| `GET /api/v1/purposes?host=` | purpose metadata for a host |
| `POST /api/v1/purposes` | import an application manifest; `DELETE /purposes/{id}` removes one entry |
| `GET/POST /api/v1/policy/bundle` | export or restore a configuration bundle (no history, decisions, tokens or keys) |
| `POST /api/v1/agent/hello` | host-agent registration; agent token |
| `POST /api/v1/agent/events` | host-agent process/connection/actual batch; agent token |
| `GET /api/v1/agent/policy` | active policy, profile and mode for an agent; agent token |
| `GET /api/v1/agents` | optional host agents with counts |
| `GET /api/v1/agents/{name}/processes` | an agent's latest processes |
| `GET /api/v1/agents/{name}/connections` | an agent's latest process-attributed connections with `predicted`, `scope` (`host`, `process` or `default`: what decided it) and `actual` (`deny` only when the agent dropped it) |
| `GET /api/v1/archive` | `{enabled, bytes, files, oldest, newest}`: the long-term archive. Viewer |
| `GET /api/v1/sensors` | `[{name, version, os, arch, interfaces, first_seen, last_seen, stats, status, problems, upgrade_to, settable, config, in_effect, config_applied, takes_config}]`. `status` is `ok`, `quiet` or `struggling`; `problems` says what's going wrong now, from the difference between its last two reports; `upgrade_to` is set if it's older than the server |
| `GET /api/v1/sensors/{name}/config` | what's been asked of this name alone, `%2A` for all sensors: `{log_level, rdns, active_timeout_s, flush_s}`. Viewer |
| `PUT /api/v1/sensors/{name}/config` | replaces it; `{}` clears it. `204`, or `400`. Operator |
| `GET /api/v1/sensor/config` | what a sensor asks, with the ingest token and `X-Netgraph-Sensor`: the fleet's settings with its own on top |
| `GET /api/v1/wifi` | `[{bssid, ssid, security, channel, clients, first_seen, last_seen}]`, from monitor-mode sensors |
| `GET /api/v1/live` | server-sent events: `event: ingest` with `[{type, ts, entity, label, detail}]` per batch |
| `PUT /api/v1/devices/{mac}/label` | names a device by hand: body `{"label": "Living room TV"}` (JSON required; at most 64 printable characters), `{"label": ""}` restores the automatic name. `204`, or `400`/`404`. Read token |
| `GET /api/v1/search?q=alice&limit=20` | `[{id, kind, key, label, last_seen}]`: devices (by MAC, name or label), addresses, DNS names and networks whose key starts with `q` or whose name contains it; exact keys first, then devices, then the most recently seen. `q` needs two characters; `kind:q` (`device:3c:22`) searches one kind. `limit` is at most 100 (default 20). Read token |
| `GET /api/v1/frame` | `?at=TIME&lookback=5m&scope=device:MAC&limit=N`: a recorded moment, built from the same queries as a window. Returns summary, devices, destinations, connections, DNS, Wi-Fi, sensors, anomalies and graph. `scope` applies a device, domain or IP filter. |
| `GET /api/v1/timeline` | `?from=&to=&entity=&kinds=dns,flow_open&limit=&cursor=`: the event rail, newest first. Kinds: `device_new`, `observation`, `dns`, `flow_open`, `flow_close`, `sensor`, `annotation`, `bookmark`. `cursor` is opaque. |
| `GET /api/v1/story` | `?entity=device:MAC&from=-7d&to=now`: an entity's intervals, milestones, evidence and gaps. |
| `GET /api/v1/diff` | `?at_a=&at_b=&lookback=5m&scope=`: what was added, removed or changed between two moments. |
| `GET /api/v1/autopsy` | `?kind=&ts=&device=&entity=&summary=&severity=&evidence=JSON`: a deterministic, evidence-backed reconstruction of an anomaly; no incident needs to exist. |
| `GET /api/v1/incidents` | saved investigations, newest first (`?status=&limit=`). |
| `GET /api/v1/incidents/{id}` | one incident with notes and pinned evidence. |
| `GET /api/v1/incidents/{id}/autopsy` | the incident's reel, rebuilt from what is still recorded. |
| `GET /api/v1/incidents/{id}/export` | a self-contained JSON bundle (no packets, no keys). |
| `POST /api/v1/incidents` | save an anomaly: `{anomaly, title, from?, to?}`. Read token. |
| `PATCH /api/v1/incidents/{id}` | `{status, title, summary, note, author}`; `status` is `open`, `acknowledged` or `resolved`. Read token. |
| `POST /api/v1/incidents/{id}/pin` | pin an evidence reference. Read token. |
| `DELETE /api/v1/incidents/{id}` | remove an incident and its notes/evidence. Read token. |
| `POST /api/v1/whatif` | run a proposed policy against observed traffic: `{policy, from, to}`, with `?scope=` to narrow it. Read-only; never applies a rule. See [what-if policies](usage.md#what-if-policies). Read token. |
| `POST /api/v1/ask` | grounded question answering: `{q, from, to}`. Returns claims, citations, plan and gaps. Read token. |
| `GET /api/v1/exposure` | read-only exposure inventory: weak Wi-Fi, inbound services, anomalies and stale sensors, with evidence and gaps. |
| `GET /api/v1/coverage` | which sensors saw which devices, per-sensor health and devices seen by only one sensor. |
| `GET /api/v1/airspace` | Wi-Fi APs, channels, clients, rogue flags and gaps. |
| `GET /api/v1/weather` | observed traffic buckets and a simple moving-mean forecast with a band. |
| `GET /api/v1/annotations` | human notes in the window (`?entity=` optional). |
| `POST /api/v1/annotations` | `{ts, entity?, kind?, text, author?}`; also appears on the timeline. `entity` is `kind:key`. |
| `DELETE /api/v1/annotations/{id}` | remove a note. |
| `GET /api/v1/bookmarks` | bookmarks in the window (`?entity=` optional). |
| `POST /api/v1/bookmarks` | `{ts, entity?, name}`; also appears on the timeline. |
| `DELETE /api/v1/bookmarks/{id}` | remove a bookmark. |
| `GET /api/v1/capsule` | a self-contained HTML time capsule for the window (metadata only; no packets or keys). It replays offline when the server has the web UI's files |
| `GET /api/v1/reel` | `?step=` and the graph's options: `{from, to, step, steps, precision, graph, series: [{edge, points: [[step index, up, down]]}], markers, unassigned}`: the window's graph with each edge's traffic per step, for scrubbing without asking again. `precision` is `exact`, `minute` or `hour`; `unassigned` counts bytes on no drawn edge |
| `GET /api/v1/reel/markers` | `[{ts, kind, severity, title, entity}]`: notes, bookmarks, new devices and anomalies in the window |
| `GET /api/v1/export?kind=flows` | CSV of every field the API returns for that table (`devices`, `flows`, `dns`, `facts`, `anomalies`, `wifi`). It uses the same window and filters and streams most kinds from the database, so it is not limited to what the browser loaded. Default safety caps: connections and facts 100,000 rows, lookups 50,000, Wi-Fi networks 10,000, devices and anomalies materialised in memory. Add `all=1` to stream every matching row (hard ceiling 5,000,000); the web "All CSV" uses it. Read token |
| `GET /api/v1/anomalies` | the window's [anomalies](concepts.md#anomalies), most severe first: `{from, to, since, learning, anomalies: [{kind, severity, ts, device, device_name, entity, summary, evidence}]}`. Only the `device` filter applies. Read token |
| `GET /api/v1/anomalies/mutes` | `{mutes: [{kind, device, entity, until, note, created}]}`, active mutes only. Read token |
| `POST /api/v1/anomalies/mute` | JSON body (`Content-Type: application/json`) `{kind, device, entity, until, note}`; empty fields are wildcards, `until` is unix ms (default one day). Read token |
| `DELETE /api/v1/anomalies/mute?kind=...&device=...&entity=...` | remove that exact mute. Read token |
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
Rows from hourly rollups set `connections` to the number of connections the
row stands for; they keep no packet counts, so `pkts_out` and `pkts_in` are
zero.
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
sensors call it automatically on startup and every minute. `since=MS`
restricts handshakes and group keys to records the server received at or
after that unix-millisecond time; PMKs and WEP keys are always complete. The
response is `{pmks, wep, handshakes, group_keys}`:

- `pmks`: `[{ssid, pmk}]`, the 32-byte PMK (hex) for each network in the
  server's `-wifi-key-file`. Passphrases are not sent; the server derives
  the PMKs.
- `wep`: `[{index, key}]`, the configured WEP keys (hex).
- `handshakes`: `[{bssid, sta, ssid, anonce, snonce, key_version, cipher}]`, the
  latest stored 4-way handshake nonces per client, from `wifi_key` events.
  These are broadcast in the clear and decrypt nothing on their own; with a
  network's PMK they let a restarted or additional sensor re-derive the
  pairwise key without seeing the handshake again.

  `cipher` is the pairwise cipher the station chose in message 2, so a
  restarted sensor does not have to guess between CCMP and GCMP-256 from a
  transition network's beacon.
- `group_keys`: `[{bssid, sta, ssid, key_id, anonce, snonce, descriptor,
  key_info, key_length, iv, key_data, ts}]`, the latest group key per AP and
  key ID from `wifi_gtk` events: the EAPOL-Key fields with `key_data` still
  wrapped by the client's KEK. A sensor re-derives that KEK from the PMK and
  the nonces and unwraps the GTK, so it decrypts the AP's broadcasts
  without waiting for a rekey.

`pmks` and `wep` are empty unless the server has a key file **and** an
ingest token. A server started with `-no-auth` has no credential to check,
so it refuses this endpoint entirely: it serves neither keys nor the
handshake/group-key sync records.
