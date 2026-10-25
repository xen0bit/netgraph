#!/bin/sh
# lldpd in the router's namespace, advertising the router on the LAN side
# every 5 seconds.
set -e
mkdir -p /run/lldpd
lldpd -d -S "lab router (OpenWrt-like)" &
sleep 2
lldpcli configure system hostname lab-router || true
lldpcli configure lldp tx-interval 5 || true
wait
