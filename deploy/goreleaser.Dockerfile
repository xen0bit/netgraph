# Used by goreleaser's dockers_v2: it stages each platform's binaries under
# $TARGETPLATFORM/, so this only copies the prebuilt binary in.
FROM gcr.io/distroless/static-debian12:nonroot AS server
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/netgraph /usr/bin/netgraph
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/bin/netgraph"]
CMD ["serve", "-db", "/data/netgraph.db", "-listen", ":8443"]

FROM gcr.io/distroless/static-debian12 AS sensor
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/netgraph-sensor /usr/bin/netgraph-sensor
ENTRYPOINT ["/usr/bin/netgraph-sensor"]
CMD ["run"]
