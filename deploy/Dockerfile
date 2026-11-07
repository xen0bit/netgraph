# Multi-stage build for the images, from source:
#
#   docker build -f deploy/Dockerfile --target sensor -t netgraph-sensor .
#   docker build -f deploy/Dockerfile --target server -t netgraph .
#   docker build -f deploy/Dockerfile --target agent -t netgraph-agent .
#
# Released images are built by goreleaser from its own binaries instead
# (deploy/goreleaser.Dockerfile); this file is for local use and test/lab.

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
# The ASN table is embedded when the context has one (make asn.fetch first);
# this build does not download it, so the lab stays offline.
RUN tags=embed_web; [ -s internal/asn/ip2asn-combined.tsv.gz ] && [ -s internal/asn/ip2asn.date ] && tags=$tags,embed_asn; \
    make web.build VERSION=${VERSION} \
 && go build -trimpath -ldflags "-s -w -X github.com/xen0bit/netgraph/internal/buildinfo.Version=${VERSION}" \
        -o /out/netgraph-sensor ./cmd/netgraph-sensor \
 && go build -trimpath -tags $tags -ldflags "-s -w -X github.com/xen0bit/netgraph/internal/buildinfo.Version=${VERSION}" \
        -o /out/netgraph ./cmd/netgraph \
 && go build -trimpath -ldflags "-s -w -X github.com/xen0bit/netgraph/internal/buildinfo.Version=${VERSION}" \
        -o /out/netgraph-agent ./cmd/netgraph-agent \
 && mkdir -p /out/data

# The sensor needs CAP_NET_RAW (cap_add: [NET_RAW]) and nothing else. It runs
# as root inside the container only so the capability applies without file
# caps; it holds no other privileges and writes nothing to disk.
FROM gcr.io/distroless/static-debian12 AS sensor
COPY --from=build /out/netgraph-sensor /usr/bin/netgraph-sensor
ENTRYPOINT ["/usr/bin/netgraph-sensor"]
CMD ["run"]

FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/netgraph /usr/bin/netgraph
# Owned by nonroot, so a fresh named volume mounted here is writable.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/bin/netgraph"]
CMD ["serve", "-db", "/data/netgraph.db", "-listen", ":8443"]

# The host agent reads the host's /proc, so it runs with the host's PID and
# network namespaces (pid: host, network_mode: host) and CAP_SYS_PTRACE plus
# CAP_DAC_READ_SEARCH to read other users' /proc/<pid>/fd; deploy/compose/
# agent.yml has the rest. Alpine, not distroless, for nft: -enforce=nftables
# runs it (and needs CAP_NET_ADMIN too).
FROM alpine:3.22 AS agent
RUN apk add --no-cache nftables
COPY --from=build /out/netgraph-agent /usr/bin/netgraph-agent
ENTRYPOINT ["/usr/bin/netgraph-agent"]
