package sources

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
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

// ValidLeaseFormat says whether a format is one this reads.
func ValidLeaseFormat(f string) bool { return f == "" || f == "dnsmasq" || f == "isc" || f == "kea" }

// ParseLeases reads a lease file in the given format. Whatever the format, an unexpected
// line is skipped: the file belongs to another program.
func ParseLeases(format, text string) []Lease {
	switch format {
	case "isc":
		return ParseISCLeases(text)
	case "kea":
		return ParseKeaLeases(text)
	}
	return ParseDNSMasqLeases(text)
}

// latest keeps one lease per address, the last said, in the order addresses first appeared.
// ISC and Kea both append, so a file's earlier lines are out of date.
type latest struct {
	at  map[netip.Addr]int
	out []Lease
}

func (k *latest) put(l Lease, keep bool) {
	if k.at == nil {
		k.at = map[netip.Addr]int{}
	}
	i, ok := k.at[l.IP]
	switch {
	case ok && keep:
		k.out[i] = l
	case ok:
		k.out[i].MAC = "" // released or expired since: dropped by leases()
	case keep && len(k.out) < maxLeases:
		k.at[l.IP] = len(k.out)
		k.out = append(k.out, l)
	}
}

func (k *latest) leases() []Lease {
	return slices.DeleteFunc(k.out, func(l Lease) bool { return l.MAC == "" })
}

// ParseISCLeases reads ISC dhcpd's dhcpd.leases, as OPNsense and pfSense also keep:
// blocks of "lease 192.168.1.5 { ...; }", where only an active one means anything.
func ParseISCLeases(text string) []Lease {
	var k latest
	var cur Lease
	in, active := false, false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !in {
			f := strings.Fields(line)
			if len(f) == 3 && f[0] == "lease" && f[2] == "{" {
				if ip, err := netip.ParseAddr(f[1]); err == nil {
					cur, in, active = Lease{IP: ip.Unmap()}, true, false
				}
			}
			continue
		}
		if line == "}" {
			in = false
			k.put(cur, active && cur.MAC != "")
			continue
		}
		line = strings.TrimSuffix(line, ";")
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "binding" && f[1] == "state":
			active = f[2] == "active"
		case len(f) >= 3 && f[0] == "hardware" && f[1] == "ethernet":
			if mac, err := net.ParseMAC(f[2]); err == nil && len(mac) == 6 {
				cur.MAC = mac.String()
			}
		case len(f) >= 2 && f[0] == "client-hostname":
			cur.Hostname = cleanHostname(strings.Trim(strings.Join(f[1:], " "), `"`))
		case len(f) >= 2 && f[0] == "ends":
			cur.Expires = iscTime(f[1:])
		}
	}
	return k.leases()
}

// iscTime reads "4 2026/10/29 22:00:00" (always UTC), "epoch 1793232000; # ...", or "never".
func iscTime(f []string) time.Time {
	if f[0] == "epoch" && len(f) >= 2 {
		if v, err := strconv.ParseInt(strings.TrimSuffix(f[1], ";"), 10, 40); err == nil && v > 0 {
			return time.Unix(v, 0)
		}
		return time.Time{}
	}
	if len(f) >= 3 {
		if t, err := time.Parse("2006/01/02 15:04:05", f[1]+" "+f[2]); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ParseKeaLeases reads the CSV files of Kea's memfile backend, DHCPv4 or DHCPv6, by the
// names in the header, since columns have been added over the years.
func ParseKeaLeases(text string) []Lease {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return nil
	}
	col := map[string]int{}
	for i, name := range strings.Split(strings.TrimRight(lines[0], "\r"), ",") {
		col[name] = i
	}
	ipAt, ok1 := col["address"]
	macAt, ok2 := col["hwaddr"]
	if !ok1 || !ok2 {
		return nil
	}
	field := func(f []string, name string) string {
		if i, ok := col[name]; ok && i < len(f) {
			return f[i]
		}
		return ""
	}
	var k latest
	for _, line := range lines[1:] {
		f := strings.Split(strings.TrimRight(line, "\r"), ",")
		if len(f) <= max(ipAt, macAt) {
			continue
		}
		ip, err := netip.ParseAddr(f[ipAt])
		if err != nil {
			continue
		}
		l := Lease{IP: ip.Unmap()}
		if mac, err := net.ParseMAC(f[macAt]); err == nil && len(mac) == 6 {
			l.MAC = mac.String()
		}
		l.Hostname = cleanHostname(field(f, "hostname"))
		if v, err := strconv.ParseInt(field(f, "expire"), 10, 40); err == nil && v > 0 {
			l.Expires = time.Unix(v, 0)
		}
		// 0 is in use; 1 declined; 2 expired and reclaimed. Very old files have no such column.
		state := field(f, "state")
		k.put(l, l.MAC != "" && (state == "" || state == "0"))
	}
	return k.leases()
}

func cleanHostname(h string) string {
	h = strings.TrimSuffix(h, ".")
	if len(h) > 253 {
		return ""
	}
	return h
}

// LeaseEvents says what a lease means, as if the sensor had seen the DHCP exchange.
func LeaseEvents(l Lease, now time.Time) []wire.Event {
	var secs uint32
	if d := l.Expires.Sub(now); !l.Expires.IsZero() && d > 0 {
		secs = uint32(min(d, 365*24*time.Hour) / time.Second)
	}
	if l.IP.Is6() { // a DHCP event here means DHCPv4's fields
		evs := []wire.Event{{Type: wire.TypeBinding, TS: now, Binding: &wire.Binding{MAC: l.MAC, IP: l.IP, Source: "lease"}}}
		if l.Hostname != "" {
			evs = append(evs, wire.Event{Type: wire.TypeName, TS: now, Name: &wire.Name{MAC: l.MAC, IP: l.IP, Name: l.Hostname, Proto: "dhcp"}})
		}
		return evs
	}
	return []wire.Event{
		{Type: wire.TypeDHCP, TS: now, DHCP: &wire.DHCP{Version: 4, MsgType: "ACK", MAC: l.MAC, YourIP: l.IP, Hostname: l.Hostname, LeaseSecs: secs}},
		{Type: wire.TypeBinding, TS: now, Binding: &wire.Binding{MAC: l.MAC, IP: l.IP, Source: "lease"}},
	}
}
