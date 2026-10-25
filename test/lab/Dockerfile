# One image for every lab role: router (dnsmasq), web server, laptop,
# printer (avahi), NAS (nmbd), TV (SSDP) and switch (lldpd). Real daemons
# where they exist, labapp where a protocol needs a client or server.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY apps/go.mod apps/go.sum ./
RUN go mod download
COPY apps/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /labapp .

FROM alpine:3.21
RUN apk add --no-cache dnsmasq avahi samba-server lldpd curl bind-tools iproute2 tcpdump tshark
COPY --from=build /labapp /usr/local/bin/labapp
COPY config/ /lab/
RUN chmod +x /lab/*.sh
