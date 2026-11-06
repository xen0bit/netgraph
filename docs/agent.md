# Optional host agent

`netgraph-agent` is an optional Linux host component. It is separate from
`netgraph-sensor`: the sensor stays a small, portable, stateless passive
capture agent, while the host agent identifies local processes and may
enforce the active policy on the machine it runs on.

The server works unchanged when no agent is connected. An agent failure never
affects sensors or stored network history.

## What it reports

- process identity: PID, PPID, UID, executable path, command line, executable
  SHA-256 (`sha256:...` as the current code ID);
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

Prediction is always on. Enforcement is opt-in and currently Linux-only:

```sh
sudo netgraph-agent -enforce=nftables -apply ...
```

Without `-apply`, the nftables enforcer runs in **dry-run** mode and only
reports what it would do. With `-apply`, it creates a dedicated
`inet netgraph_agent` table and installs drop rules for denied remote
addresses. Allow and ask decisions are reported, not silently enforced.
Stopping the agent removes the dedicated table.

The server never claims that an agent result was enforced unless the agent
reports an actual action. The API keeps `predicted` and `actual` separate.

## Privacy and safety

- The agent is opt-in and uses a separate token.
- It reads `/proc`; it does not dump memory, payloads or credentials.
- The executable hash is bounded and cached.
- It does not execute paths, commands or URLs from the server.
- `nftables` changes are confined to one dedicated table and are off by
  default.
- macOS support (Network Extension / Endpoint Security) is a separate future
  platform implementation, not part of this Linux agent.
