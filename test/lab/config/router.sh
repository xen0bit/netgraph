#!/bin/sh
# Routes between the LAN (10.77.0.0/24) and the "internet" (198.18.0.0/24),
# serving DHCP and DNS to the LAN.
set -e
exec dnsmasq -k -C /lab/dnsmasq.conf
