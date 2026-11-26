# netgraph-agent on Windows

`netgraph-agent.exe` is the optional host agent: it reports this machine's
TCP sockets and the programs behind them to a netgraph server, which matches
them to the connections a sensor saw. It observes only — there is no
enforcement on Windows — and it sends program names, not command lines,
unless you add `-cmdlines`.

All builds are static and cgo-free. Windows agents see TCP only: the system's
tables give UDP sockets no peer, so UDP traffic stays unnamed.

## Install as a service

1. Copy `netgraph-agent.exe` somewhere stable, for example
   `C:\Program Files\netgraph\netgraph-agent.exe`.
2. Write the server's agent token to
   `C:\ProgramData\netgraph\agent.token`, readable by Administrators and
   SYSTEM only, not by ordinary users. It is the same value as the server's
   `-agent-token-file`.
3. From an **elevated** PowerShell prompt, run:

```powershell
.\install-service.ps1 -Server https://netgraph.lan:8443 `
  -TokenFile C:\ProgramData\netgraph\agent.token
```

The script creates the service named `netgraph-agent` with `sc.exe`, sets it
to start automatically, and starts it. The service name is fixed: the agent
registers with the Service Control Manager under exactly that name, so
installing it under another name would start and then fail. LocalSystem is
the default account and can read other users' processes.

Useful flags go through `-AgentArgs`, for example a stable name when the
hostname changes, or a private CA:

```powershell
.\install-service.ps1 -CaFile C:\ProgramData\netgraph\ca.pem `
  -AgentArgs @('-name','office-pc','-interval','5s')
```

To test without installing, run one scan in a console:

```powershell
.\netgraph-agent.exe -server https://netgraph.lan:8443 `
  -token-file C:\ProgramData\netgraph\agent.token -once
```

## Remove

```powershell
.\install-service.ps1 -Uninstall
```

This stops and deletes the service. The binary and token file are left in
place. To change the server or flags, remove the service and install it
again (or edit it with `sc.exe config netgraph-agent binPath= "..."`).

## Logs and checks

The agent's log goes to stderr, which a service has no console for: check the
server under **Manage → Host agents**, and `netgraph agents list` prints its
last report. An agent behind NAT from the sensor names nothing until it runs
where the sensor's addresses are.
