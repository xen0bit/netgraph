#!/bin/sh
# The scripted user. Every step is logged to /shared/events.log as
# "<unix ms> <step>", which the lab test reads to build its windows.
set -u
log() { echo "$(( $(date +%s) * 1000 )) $1" >> /shared/events.log; }
: > /shared/events.log
sleep "${START_DELAY:-8}"

# DHCP: ask for our lease with a hostname and vendor class (and do not
# reconfigure the interface Docker already set up).
udhcpc -i eth0 -n -q -f -t 3 -s /bin/true -x hostname:lab-laptop -V lab-vendor-class && log dhcp
ip route replace default via 10.77.0.10
echo "nameserver 10.77.0.10" > /etc/resolv.conf

log start
dig +short @10.77.0.10 www.lab.test A && log dns-www
curl -sk https://www.lab.test/ && log https-www
# A connection held open for 90 s: it spans every window the test asks about.
log hold-start
curl -sk "https://hold.lab.test/hold?secs=90" -o /dev/null && log hold-end &
sleep 5
labapp h3get https://quic.lab.test/ && log h3-quic
sleep 5
curl -s -A "lab-agent/1.0" http://plain.lab.test/ && log http-plain
sleep 5
dig @10.77.0.10 nx.lab.test A > /dev/null; log dns-nx
curl -sk https://alias.lab.test/ && log https-alias
wait
log done
touch /shared/done
sleep infinity
