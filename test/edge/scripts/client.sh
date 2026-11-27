#!/bin/sh
# A real WireGuard client (wireguard-go via wg-quick) that reaches the inside
# network through the edge and moves some TCP across it, then marks itself
# done for the test.
set -eu
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${CLIENT_PRIVATE}
Address = ${CLIENT_TUN_IP}/24

[Peer]
PublicKey = ${SERVER_PUBLIC}
PresharedKey = ${PSK}
Endpoint = 198.18.1.10:51820
AllowedIPs = ${SERVER_TUN_IP}/32, 10.78.0.0/24
PersistentKeepalive = 15
CONF
wg-quick up wg0
for i in $(seq 1 30); do
  ping -c1 -W1 10.78.0.30 >/dev/null 2>&1 && break
  sleep 1
done
iperf3 -c 10.78.0.30 -n 2M
touch /tmp/done
echo "wg-client: done"
while true; do sleep 3600; done
