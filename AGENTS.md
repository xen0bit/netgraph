# AGENTS.md — working on netgraph

## Layout

| Path | What |
|---|---|
| `cmd/netgraph-sensor` | router agent. **Must not import SQLite, d2 or the TUI**; `deps_test.go` enforces it (modernc sqlite does not build for mips; d2 adds ~20 MB) |
| `cmd/netgraph` | server, CLI, TUI |
| `cmd/web` | WASM entrypoint (`js && wasm`), served by `netgraph serve` |
| `internal/buildinfo` | version symbols stamped by the Makefile and goreleaser |
| `deploy/` | Dockerfiles, compose files for sidecar and host deployments |
| `packaging/` | systemd units, OpenWrt procd init and UCI config |
| `test/lab` | docker-compose lab, `go test -tags lab` (`make lab`) |

Planned packages: `internal/{capture,decode,flow,wire,ingest,correlate,enrich/oui,store,query,graph,api,tui}`, `web/`.

## Rules

- Everything is `CGO_ENABLED=0`. Run `make cross` before you add a dependency;
  the sensor must still build for mips/mipsle softfloat and arm v5.
- The target lists are kept in three places: `Makefile` (`SENSOR_TARGETS`,
  `SERVER_TARGETS`), `.goreleaser.yaml` and the `cross` job in CI. Change all
  three together.
- d2 scripts must quote every key. An unquoted `example.com` or IP address is
  parsed as nested containers.
- Time windows are half-open `[t0, t1)`. A flow belongs to a window when
  `t_start < t1 && t_end >= t0`, and is classified `carried`/`opened`/`closed`.
  A DNS answer is valid over `[ts, ts+ttl]`.
- Decoders are pure functions over packet bytes, each with a `Fuzz*` target.

## Tooling

go 1.27, golangci-lint v2.14.0, goreleaser v2, govulncheck, actionlint,
Docker with compose v2+.
