package sensor

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/xen0bit/netgraph/internal/wire"
)

// defaultLocal is what counts as a LAN address without interface prefixes:
// the private, link-local and CGNAT ranges. A sensor adds its capture
// interfaces' own prefixes on top (LocalChecker), which covers a LAN with
// public IPv6.
var defaultLocal = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// LocalChecker returns a function that reports whether an address is on the
// LAN: in a private range or in a prefix held by one of the sensor's capture
// interfaces.
func LocalChecker(ifaces []wire.Interface) func(netip.Addr) bool {
	var extra []netip.Prefix
	for _, ifc := range ifaces {
		for _, p := range ifc.Prefixes {
			if p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
				continue
			}
			extra = append(extra, p.Masked())
		}
	}
	return func(a netip.Addr) bool { return isLocal(a, extra) }
}

// LocalAddr reports whether a is in one of the default LAN ranges.
func LocalAddr(a netip.Addr) bool { return isLocal(a, nil) }

func isLocal(a netip.Addr, extra []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range defaultLocal {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range extra {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ResolveInterface turns an -iface value into an interface name. The value
// is a name ("br-lan"), or an address or prefix ("192.168.1.1",
// "10.77.0.0/24") naming the interface that holds it — handy where names
// are not stable, such as a container attached to several networks.
func ResolveInterface(v string) (string, error) {
	v = strings.TrimSpace(v)
	addr, aerr := netip.ParseAddr(v)
	prefix, perr := netip.ParsePrefix(v)
	if aerr != nil && perr != nil {
		return v, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			if aerr == nil && p.Addr() == addr.Unmap() || perr == nil && prefix.Contains(p.Addr()) {
				return ifc.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface holds %s", v)
}
