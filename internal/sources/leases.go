package sources

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Lease is one DHCP lease a server knows of.
type Lease struct {
	MAC      string
	IP       netip.Addr
	Hostname string
	Expires  time.Time
}

// maxLeases bounds what one file can make the server hold.
const maxLeases = 65536

// ParseDNSMasqLeases reads dnsmasq's lease file: "expiry mac ip hostname clientid". A
// lease with no fixed expiry says 0. Hostnames are what the client said, so they're
// passed along for ingest to treat like any other name off the network.
func ParseDNSMasqLeases(text string) []Lease {
	var out []Lease
	for _, line := range strings.Split(text, "\n") {
		if len(out) >= maxLeases {
			break
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "duid" {
			continue
		}
		mac, err := net.ParseMAC(f[1])
		if err != nil || len(mac) != 6 {
			continue
		}
		ip, err := netip.ParseAddr(f[2])
		if err != nil {
			continue
		}
		l := Lease{MAC: mac.String(), IP: ip.Unmap()}
		if f[3] != "*" && len(f[3]) <= 253 {
			l.Hostname = f[3]
		}
		var expiry int64
		for _, c := range f[0] {
			if c < '0' || c > '9' || expiry > 1<<40 {
				expiry = 0
				break
			}
			expiry = expiry*10 + int64(c-'0')
		}
		if expiry > 0 {
			l.Expires = time.Unix(expiry, 0)
		}
		out = append(out, l)
	}
	return out
}

// LeaseEvents says what a lease means, as if the sensor had seen the DHCP exchange.
func LeaseEvents(l Lease, now time.Time) []wire.Event {
	var secs uint32
	if d := l.Expires.Sub(now); !l.Expires.IsZero() && d > 0 {
		secs = uint32(min(d, 365*24*time.Hour) / time.Second)
	}
	return []wire.Event{
		{Type: wire.TypeDHCP, TS: now, DHCP: &wire.DHCP{Version: 4, MsgType: "ACK", MAC: l.MAC, YourIP: l.IP, Hostname: l.Hostname, LeaseSecs: secs}},
		{Type: wire.TypeBinding, TS: now, Binding: &wire.Binding{MAC: l.MAC, IP: l.IP, Source: "lease"}},
	}
}
