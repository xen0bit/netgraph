#!/bin/sh
# strongSwan road warrior: connect to the edge's IKEv2 listener, move some TCP
# to the inside network through the tunnel, mark itself done, stay connected.
set -eu
/usr/lib/ipsec/charon &
i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
  i=$((i + 1)); [ "$i" -gt 80 ] && { echo "vici never appeared"; exit 1; }
  sleep 0.25
done
swanctl --load-all
i=1
until swanctl --initiate --child edge; do
  i=$((i + 1)); [ "$i" -gt 30 ] && { echo "could not connect"; exit 1; }
  sleep 2
done
for i in $(seq 1 30); do
  ping -c1 -W1 10.78.0.30 >/dev/null 2>&1 && break
  sleep 1
done
iperf3 -c 10.78.0.30 -n 2M
touch /tmp/done
echo "ikev2-client: done"
wait
