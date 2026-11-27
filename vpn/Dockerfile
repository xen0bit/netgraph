# veepin runtime image — used by the interop test harness (tests/interop) to run
# the real veepin binary in containers against strongSwan.
#
# The binary is pure-Go and CGO-free (its one dependency, golang.org/x/crypto, is
# too), so the build is fully static and the runtime image only needs the
# userspace networking tools it shells out to (ip/iptables/sysctl) plus ping for
# the data-path assertion. tcpdump is here for the capture cells that record a
# peer's traffic into internal/capture/goldens: the peer images cannot be relied
# on to carry it, and the veepin container is the one service in every cell.
# TUN access
# (/dev/net/tun) and CAP_NET_ADMIN are granted at run time by compose, not baked
# into the image.

# --- build stage: static, CGO-free binaries ---
# The build context is the netgraph repository root (vpn/ is a directory of the
# netgraph module), and vpn/Dockerfile.dockerignore admits only go.mod, go.sum
# and vpn/. No `go mod download`: the module file lists netgraph's server
# dependencies too (SQLite, d2), and the build fetches only what veepin imports.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vpn ./vpn
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ ./vpn/cmd/veepin

# --- runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping iperf3 procps ca-certificates openssl socat \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/veepin /usr/local/bin/
# Entrypoint scripts are bind-mounted by compose; default to a shell.
CMD ["/bin/bash"]
