#!/bin/sh
# netgraph-edge for the edge lab: one WireGuard listener, NATed onto the
# inside network. The listener file is written here because hostnet needs the
# WAN interface's name, which Docker does not promise.
set -eu
wan=$(ip -o -4 addr show | awk '$4 ~ /^10\.78\.0\./ {print $2; exit}')
mkdir -p /etc/netgraph-edge/listeners
cat > /etc/netgraph-edge/listeners/office.json <<JSON
{
  "name": "office",
  "protocol": "wireguard",
  "setup_nat": true,
  "wan": "${wan}",
  "options": {
    "private-key": "${SERVER_PRIVATE}",
    "address": "${SERVER_TUN_IP}/24",
    "listen-port": "51820",
    "tun": "wg-office",
    "peer-public-key": "${CLIENT_PUBLIC}",
    "peer-preshared-key": "${PSK}",
    "peer-allowed-ips": "${CLIENT_TUN_IP}/32"
  }
}
JSON
printf 'alice:wonderland\n' > /etc/netgraph-edge/eap-users
cat > /etc/netgraph-edge/listeners/remote.json <<JSON
{
  "name": "remote",
  "protocol": "ikev2",
  "setup_nat": true,
  "wan": "${wan}",
  "options": {
    "psk": "edge-lab-psk",
    "id": "vpn.example.com",
    "public": "198.18.1.10",
    "pool": "10.11.11.0/24",
    "tun": "ike-remote",
    "eap-users": "/etc/netgraph-edge/eap-users"
  }
}
JSON
echo "edge: WAN is ${wan}"
exec netgraph-edge run -server http://10.78.0.20:8443 -name edge-lab \
  -active-timeout 5s -flush 1s -log-level debug
