# Multi-stage build for both images, from source:
#
#   docker build -f deploy/Dockerfile --target sensor -t netgraph-sensor .
#   docker build -f deploy/Dockerfile --target server -t netgraph .
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
RUN make web.build VERSION=${VERSION} \
 && go build -trimpath -ldflags "-s -w -X github.com/xen0bit/netgraph/internal/buildinfo.Version=${VERSION}" \
        -o /out/netgraph-sensor ./cmd/netgraph-sensor \
 && go build -trimpath -tags embed_web -ldflags "-s -w -X github.com/xen0bit/netgraph/internal/buildinfo.Version=${VERSION}" \
        -o /out/netgraph ./cmd/netgraph

# The sensor needs CAP_NET_RAW (cap_add: [NET_RAW]) and nothing else. It runs
# as root inside the container only so the capability applies without file
# caps; it holds no other privileges and writes nothing to disk.
FROM gcr.io/distroless/static-debian12 AS sensor
COPY --from=build /out/netgraph-sensor /usr/bin/netgraph-sensor
ENTRYPOINT ["/usr/bin/netgraph-sensor"]
CMD ["run"]

FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/netgraph /usr/bin/netgraph
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/bin/netgraph"]
CMD ["serve", "-db", "/data/netgraph.db", "-listen", ":8443"]
