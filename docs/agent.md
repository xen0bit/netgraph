# Host agent (optional)

`netgraph-agent` runs on the hosts whose programs you want named. A sensor
sees that the laptop connected to `api.example.com`; the agent on the laptop
says it was `python3`. The server matches the two, and the graph draws

```
laptop ──runs──▶ python3 ──connects──▶ api.example.com
```

It is separate from `netgraph-sensor`: the sensor stays a small, portable,
stateless passive capture on the router, and nothing depends on an agent.
The server works unchanged with none connected, and an agent failure never
affects sensors or stored history.

| Platform | Sockets from | Processes from | Enforcement |
|---|---|---|---|
| Linux (amd64, arm64, armv7, riscv64, 386) | `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/<pid>/fd`; with `-events=bpf` also the kernel's connection events | `/proc/<pid>` | opt-in, nftables |
| macOS (amd64, arm64) | `lsof -nP -iTCP -iUDP` | `ps` | none: observe only |
| Windows (amd64, arm64) | `GetExtendedTcpTable` (TCP only) | the process list and `QueryFullProcessImageName` | none: observe only |

All builds are static and cgo-free. macOS runs the system's `/usr/sbin/lsof`
and `/bin/ps` by absolute path with fixed arguments; Windows calls iphlpapi.

## What it reports

- process identity: PID, parent PID, UID (not on Windows), executable path,
  start time, and the program's name. The full command line only with
  `-cmdlines` (Linux and macOS), since arguments can hold passwords and
  tokens;
- the executable's SHA-256 (`sha256:...` as its code ID): at most 64 MiB
  read, cached until the file's size or mtime changes. On Linux it reads
  `/proc/<pid>/exe`, which reaches the running binary even from a container
  or after the file was replaced;
- each connected TCP socket, and on Linux and macOS each UDP socket
  connected to one peer (many QUIC and DNS clients use unconnected sockets,
  which name no peer and are skipped), with its owning process and direction
  (`out`, `in` when a local listener has the port, `local`). IPv4 peers of
  dual-stack sockets are reported as IPv4, as the sensor sees them;
- the policy prediction (`allow`, `deny`, `ask`) and, when enforcing, what
  was done.

It does **not** send packet payloads, credentials, DNS queries, file
contents or environment variables, and it never runs a command, path or URL
from the server.

The agent polls (`-interval`: 2 s on Linux, 10 s on macOS and Windows), so
a connection that opens and closes between two scans is never seen: a
200 ms HTTP request usually isn't, a page load's keep-alive connection
usually is. [Connection events](#connection-events-linux--eventsbpf) name
the rest. On Linux a scan is cheap: the agent remembers which process
holds each socket, and looks through `/proc/<pid>/fd` only for sockets it
hasn't placed yet, first in the processes that already hold sockets, then
in processes started since the last scan. It reads a process's identity as
soon as it finds the socket, so a program that runs for a moment can still
be named. An open connection that hasn't changed, and a process that
hasn't, is sent again every `-refresh` (a minute), which keeps its
`last_seen` current for matching.

## Connection events (Linux, `-events=bpf`)

Polling can't name what it doesn't see. Behind a reverse proxy most
connections last milliseconds: a health check, a short API call, a
`wget` in a script. With `-events=bpf` (or `NETGRAPH_AGENT_EVENTS=bpf`) the
kernel tells the agent as each one happens, from small BPF programs
(`internal/agent/linux/bpf/src/conn.c`) attached to:

| Hook | What it reports |
|---|---|
| `tcp_connect` | an outbound TCP connection |
| `inet_csk_accept` (on return) | an accepted TCP connection, in the process that accepted it |
| `ip_send_skb`, `ip6_send_skb` | a UDP datagram, with its addresses as sent |
| `ping_v4_sendmsg`, `ping_v6_sendmsg`, `raw_sendmsg`, `rawv6_sendmsg` | an ICMP echo request, with its echo identifier |

Each event carries the process (PID, parent, start time, user, command
name) and the socket's inode. The agent reads the process from `/proc` as
the event arrives and checks its start time, so a reused PID is never
mistaken for it. A program that already exited is named by the kernel's
command name alone. UDP and pings are reported once per process and
destination every five seconds, not per packet. Polling continues beside
the events: it keeps open connections' `last_seen` moving, and covers
anything a kernel can't hook (the agent logs what). Events also tell the
scanner which process holds a socket, so it walks `/proc/<pid>/fd` less.

The programs only read: they change no packet, socket or decision. They
read no payload beyond a UDP header or the ICMP header a program sends,
and report only sockets in the agent's own network namespace. Requirements:

- `CAP_BPF` and `CAP_PERFMON` (or root). In a container, add them to
  `cap_add`; the `.deb`/`.rpm` unit allows them (`systemctl edit
  netgraph-agent` to add them to `AmbientCapabilities`). They let a
  process read kernel memory through BPF: grant them only where you want
  this;
- a kernel with BTF (`/sys/kernel/btf/vmlinux`) and BPF trampolines: 5.17
  or later on amd64, 6.0 on arm64. 32-bit ARM and 386 kernels have no
  trampolines: there `-events=bpf` fails to start, and polling is the
  mode;
- the host's PID namespace (`pid: host` in a container), since the kernel
  names processes by their host PIDs.

An ICMP echo is matched by its identifier, which the sensor records as the
pinger's port. An unbound socket's source address isn't decided until the
route is chosen, so the agent asks the routing table, in the same network
namespace, which address it sends from to that destination.

`make bpf` rebuilds the objects (clang, in Docker); they are checked in,
so building the agent needs no clang. `make bpf-test` loads them into the
running kernel and checks each kind of event.

## Ancestry

On Linux each socket's owner comes with its parents (up to eight, as far as
the agent can read them), so a program's details say who started it:
`sshd (10) › sshd-session (20) › bash (31)`.

## Programs in the graph and the tables

The server matches each of the sensor's connections to an agent's socket
with the same protocol, addresses and ports, seen while the connection was
open (two minutes of slack either way). Then:

- **Graph**: with **Processes** (default on; `processes=0` in the API,
  `-processes=false` for `netgraph graph`) a device's connections hang off
  the programs that made or accepted them, joined by `runs` edges; the
  device keeps its totals. A lookup is folded into the program's edge when
  one program went there. A LAN connection between two hosts with agents is
  drawn program to program. Connections no agent named stay on the device.
- **Processes** tab: every program the agents reported in the window, with
  its host and device, PIDs, command lines, who started it, how many
  connections it made, accepted and kept on the host (loopback, which no
  sensor sees), what it talked to and served, and the bytes of the matched
  connections (`GET /api/v1/processes`).
- **Process details**: click a program on the map for its connections, PIDs,
  each PID's command line (the program alone without `-cmdlines`), the
  processes that started it,
  executable path and code ID (`GET /api/v1/entity?id=process:<device>/<name>`).
- **Flows**: the Connections table, the device panel, `netgraph query flows`
  and `GET /api/v1/flows` carry `process`, `pid`, `agent` and, for a LAN
  connection whose other end runs an agent, `peer_process`.

The sensor and the agent must see the same addresses:

- a host behind NAT from the sensor's point of view (a VM on a NAT network,
  a container on a bridge network) keeps addresses of its own, so nothing
  matches. Run the agent where the sensor's addresses are: on the VM itself,
  or in the container's network namespace (as in `test/lab`);
- programs inside containers have their own network namespace. An agent on
  the Docker host sees their published ports only as `docker-proxy` (or not
  at all, with NAT); run one in the container's namespace to name them;
- hour-precision windows (longer than raw retention) come from rollups that
  keep no ports, so they name no programs.

## Server setup

Give agents a token of their own, separate from the sensors' and readers':

```sh
openssl rand -hex 32 | sudo tee /etc/netgraph/agent.token >/dev/null
netgraph serve -agent-token-file /etc/netgraph/agent.token ...   # or $NETGRAPH_AGENT_TOKEN
```

Without one, the agent endpoints are off.

| Endpoint (agent token) | |
|---|---|
| `POST /api/v1/agent/hello` | register host, OS, architecture, version and capabilities |
| `POST /api/v1/agent/events` | processes, connections and actual results |
| `GET /api/v1/agent/policy` | active policy, profile and mode |

| Endpoint (read token) | |
|---|---|
| `GET /api/v1/agents` | agents with process and connection counts |
| `GET /api/v1/agents/{name}/processes` | latest processes |
| `GET /api/v1/agents/{name}/connections` | latest attributed connections |

CLI: `netgraph agents list`, `netgraph agents processes -agent NAME`,
`netgraph agents connections -agent NAME`. The web UI lists agents under
Manage.

## Installing

Every platform takes the same flags: `-server URL` (or `$NETGRAPH_SERVER`),
`-token-file FILE` (or `$NETGRAPH_AGENT_TOKEN`), `-name` (or
`$NETGRAPH_AGENT_NAME`; default: the host name), `-ca-file` for a private
CA, `-interval`, `-refresh`, `-events` (`poll`, or `bpf` on Linux: see
[Connection events](#connection-events-linux--eventsbpf)), and `-once` (one
scan and upload, to test a setup). See [Deployment](deployment.md#host-agents)
for where agents fit.

### Linux with systemd

The `.deb`, `.rpm` and `.apk` packages install `netgraph-agent.service` and
`/etc/netgraph/agent.conf`:

```sh
sudo apt install ./netgraph-agent_<version>_linux_amd64.deb
sudoedit /etc/netgraph/agent.conf     # NETGRAPH_AGENT_ARGS=-server https://netgraph.lan:8443
echo "<agent token>" | sudo tee /etc/netgraph/agent.token >/dev/null && sudo chmod 600 /etc/netgraph/agent.token
sudo systemctl enable --now netgraph-agent
```

The unit runs as a dynamic, unprivileged user with `CAP_SYS_PTRACE` (read
access to other users' `/proc/<pid>/fd`; it never attaches to a process) and
`CAP_DAC_READ_SEARCH`. Without them it sees only its own processes.

### Linux in Docker

`deploy/compose/agent.yml` runs `ghcr.io/xen0bit/netgraph-agent` with the
host's PID and network namespaces (`pid: host`, `network_mode: host`), which
is what lets it see the host's processes and sockets:

```sh
NETGRAPH_AGENT_TOKEN=... NETGRAPH_SERVER=https://netgraph.lan:8443 \
  docker compose -f deploy/compose/agent.yml up -d
```

To name one container's programs instead, share that container's
namespaces, as the lab does: `pid: "service:app"` and
`network_mode: "service:app"`.

When several containers share one network namespace (backends joined to a
reverse proxy with `network_mode: service:proxy`, and a sidecar sensor
capturing its `eth0`), each still has a PID namespace of its own. Join the
network namespace and the host's PID namespace: the agent reads that
namespace's sockets and finds their owners among all the host's processes,
so one agent names every container's programs. `deploy/compose/sidecar.yml`
has it as the `agent` profile:

```yaml
netgraph-agent:
  image: ghcr.io/xen0bit/netgraph-agent:latest
  network_mode: "service:proxy"
  pid: host
  cap_drop: [ALL]
  cap_add: [SYS_PTRACE, DAC_READ_SEARCH]
  read_only: true
  environment:
    NETGRAPH_AGENT_TOKEN: ...
    NETGRAPH_AGENT_NAME: proxy
  command: ["-server", "http://127.0.0.1:8443"]   # a server in the same namespace
```

Docker's default AppArmor profile lets it read other containers' processes,
which run under the same profile, but not the host's own: a socket in the
namespace held by a process outside any container (rare) stays unnamed,
unless the agent runs with `security_opt: [apparmor=unconfined]`.

### macOS

The darwin archive carries `packaging/macos/netgraph-agent.plist`, a launchd
daemon; its comments have the install commands. As root it sees every user's
sockets.

### Windows

Run it as a service from an elevated prompt (elevated, it can read almost
every process's image):

```bat
mkdir "C:\ProgramData\netgraph"
rem put the agent token in C:\ProgramData\netgraph\agent.token, readable by Administrators only
sc.exe create netgraph-agent start= auto binPath= "\"C:\Program Files\netgraph\netgraph-agent.exe\" -server https://netgraph.lan:8443 -token-file C:\ProgramData\netgraph\agent.token"
sc.exe start netgraph-agent
```

It reports TCP only: the Windows tables give UDP sockets no peer.

## Enforcement (Linux)

Prediction is always on: each connection is evaluated against the server's
active policy. `-enforce=nftables` adds enforcement, which is a dry run (it
reports what it would drop) unless `-apply` is also given:

```sh
sudo netgraph-agent -enforce=nftables -apply ...
```

The agent then owns one table, `inet netgraph_agent` (`-nft-table`), and
replaces it whole in a single `nft -f` transaction whenever the set of drops
changes; on exit it deletes it. It needs `nft` and `CAP_NET_ADMIN` (in the
container: `cap_add: [NET_ADMIN]`; under systemd: add it to
`AmbientCapabilities`). It drops a destination (address, and protocol and
port when known) only when:

- an explicit **deny rule** matched: never the policy's default, since a
  default egress of deny would cut the host off;
- that rule applies to the whole host (local `any`). A rule for one app,
  process or owner is reported as not enforced: nftables can't tell programs
  apart, so a drop by address would block every program;
- the address is not the netgraph server's.

The agent sees a connection by polling, so the first packets of a denied
connection have already left; the drop stops the rest and later ones. Allow
and ask are never enforced (nothing can ask), and the agent reports
`actual: none` with the reason. The API keeps `predicted` and `actual`
separate, with `scope` (`host`, `process`, `default`) saying what decided.

macOS and Windows agents refuse `-enforce`: they would need pf or a Network
Extension, or the Windows Filtering Platform, and netgraph changes no
firewall it doesn't own.

Rules match what the agent can see: the remote address, port, protocol and
the program's name. It does not see DNS or TLS names, so `domain` and `host`
rules don't match on the agent.

## Privacy and safety

- The agent is opt-in and uses a separate token.
- It reads process and socket tables; it does not dump memory, payloads or
  credentials, and sends no arguments unless `-cmdlines`.
- Processes and connections follow the server's raw retention and `db purge`.
  They name no MAC, so `db forget` can't find them: purge by time instead.
- In the web UI's privacy mode, agent names are replaced and executable
  paths, command lines and hashes are blanked.
- It does not execute paths, commands or URLs from the server.
- `nftables` changes are confined to one dedicated table and are off by
  default.
