package sensor

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

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
