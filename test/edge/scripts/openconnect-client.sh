#!/bin/sh
# openconnect against one of the edge's commercial-protocol listeners
# (PROTOCOL: anyconnect, gp or fortinet, on PORT): log in as USER, move some
# TCP to the inside network through the tunnel, mark done.
set -u
[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }
PIN=$(openssl x509 -in /pki/server.crt -pubkey -noout | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | openssl base64)
i=1
until echo "$PASS" | openconnect --protocol="$PROTOCOL" --user="$USER" --passwd-on-stdin \
    --servercert "pin-sha256:$PIN" --script /usr/share/vpnc-scripts/vpnc-script \
    --interface tun0 --non-inter --background "198.18.1.10:$PORT"; do
  i=$((i + 1)); [ "$i" -gt 30 ] && { echo "could not connect"; exit 1; }
  sleep 2
done
for i in $(seq 1 30); do
  ping -c1 -W1 10.78.0.30 >/dev/null 2>&1 && break
  sleep 1
done
iperf3 -c 10.78.0.30 -n 2M
touch /tmp/done
echo "$PROTOCOL-client: done"
while true; do sleep 3600; done
