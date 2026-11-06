# Optional host agent

`netgraph-agent` is an optional Linux host component. It is separate from
`netgraph-sensor`: the sensor stays a small, portable, stateless passive
capture agent, while the host agent identifies local processes and may
enforce the active policy on the machine it runs on.

The server works unchanged when no agent is connected. An agent failure never
affects sensors or stored network history.

## What it reports

- process identity: PID, PPID, UID, executable path, the program's name (the
  full command line only with `-cmdlines`: arguments can hold passwords and
  tokens), executable SHA-256 (`sha256:...` as the current code ID);
- process-attributed TCP/UDP sockets from `/proc/net/{tcp,tcp6,udp,udp6}`,
  mapped to PIDs through `/proc/<pid>/fd` socket inodes;
- a stable connection key (protocol, local address/port, remote
  address/port);
- the policy prediction (`allow`, `deny`, `ask`) and, when enforcement is on,
  the actual result.

It does **not** send packet payloads, credentials, DNS queries or file
contents. The executable hash reads at most 64 MiB and is cached until the
file's size or mtime changes.

## Server setup

Use a dedicated agent token, separate from the sensor ingest and read tokens:

```sh
export NETGRAPH_AGENT_TOKEN="$(openssl rand -hex 32)"
netgraph serve -agent-token-file /etc/netgraph/agent.token ...
```

The agent endpoints are under `/api/v1/agent/` and require that token:

| Endpoint | |
|---|---|
| `POST /api/v1/agent/hello` | register host, OS, version and capabilities |
| `POST /api/v1/agent/events` | processes, connections and actual results |
| `GET /api/v1/agent/policy` | active policy, profile and mode |

Read-only inventory is available to normal readers:

| Endpoint | |
|---|---|
| `GET /api/v1/agents` | agents with process/connection counts |
| `GET /api/v1/agents/{name}/processes` | latest processes |
| `GET /api/v1/agents/{name}/connections` | latest attributed connections |

CLI: `netgraph agents list`, `netgraph agents processes -agent NAME`,
`netgraph agents connections -agent NAME`.

## Running

```sh
sudo NETGRAPH_AGENT_TOKEN=... netgraph-agent \
  -server https://netgraph.example:8443 \
  -name laptop \
  -interval 10s
```

`-once` performs one scan and upload, useful for testing.

## Enforcement

Prediction is always on: each connection is evaluated against the server's
active policy. `-enforce=nftables` adds enforcement, which is a dry run (it
reports what it would drop) unless `-apply` is also given:

```sh
sudo netgraph-agent -enforce=nftables -apply ...
```

The agent then owns one table, `inet netgraph_agent` (`-nft-table`), and
replaces it whole in a single `nft -f` transaction whenever the set of drops
changes; on exit it deletes it. It drops a destination (address, and protocol
and port when known) only when:

- an explicit **deny rule** matched: never the policy's default, since a
  default egress of deny would cut the host off;
- that rule applies to the whole host (local `any`). A rule for one app,
  process or owner is reported as not enforced: nftables can't tell programs
  apart, so a drop by address would block every program;
- the address is not the netgraph server's.

The agent sees a connection by polling `/proc`, so the first packets of a
denied connection have already left; the drop stops the rest and later ones.
Allow and ask are never enforced (nothing can ask), and the agent reports
`actual: none` with the reason. The API keeps `predicted` and `actual`
separate, with `scope` (`host`, `process`, `default`) saying what decided.

Rules match what the agent can see: the remote address, port, protocol and
the program's name. It does not see DNS or TLS names, so `domain` and `host`
rules don't match on the agent.

## Privacy and safety

- The agent is opt-in and uses a separate token.
- It reads `/proc`; it does not dump memory, payloads or credentials.
- Processes and connections follow the server's raw retention and `db purge`.
  They name no MAC, so `db forget` can't find them: purge by time instead.
- The executable hash is bounded and cached.
- It does not execute paths, commands or URLs from the server.
- `nftables` changes are confined to one dedicated table and are off by
  default.
- macOS support (Network Extension / Endpoint Security) is a separate future
  platform implementation, not part of this Linux agent.
