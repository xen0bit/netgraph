package store

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/xen0bit/netgraph/internal/wire"
)

// localNets decides which addresses are on the LAN: the private and
// link-local ranges, plus every prefix a sensor reported on its capture
// interfaces (which covers a LAN with public IPv6).
type localNets struct {
	mu       sync.RWMutex
	prefixes map[string][]netip.Prefix // by sensor
	// own is each sensor's interface MACs and the addresses those
	// interfaces hold. A router forwards other subnets' packets under its
	// own MAC, so that MAC is evidence only for these addresses.
	own map[string]map[string][]netip.Addr // sensor -> MAC -> addresses
}

var defaultLocal = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, and Tailscale-style overlays
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

func newLocalNets() *localNets {
	return &localNets{prefixes: map[string][]netip.Prefix{}, own: map[string]map[string][]netip.Addr{}}
}

func (n *localNets) addHello(sensor string, h *wire.Hello) {
	var ps []netip.Prefix
	own := map[string][]netip.Addr{}
	for _, ifc := range h.Interfaces {
		if hw, err := net.ParseMAC(ifc.MAC); err == nil {
			addrs := own[hw.String()]
			for _, p := range ifc.Prefixes {
				addrs = append(addrs, p.Addr().Unmap())
			}
			own[hw.String()] = addrs
		}
		for _, p := range ifc.Prefixes {
			if p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
				continue
			}
			ps = append(ps, p.Masked())
		}
	}
	n.mu.Lock()
	n.prefixes[sensor] = ps
	n.own[sensor] = own
	n.mu.Unlock()
}

// forwarded reports whether a packet from (or to) mac about address a was
// forwarded by a sensor's router rather than sent by a: mac is one of a
// sensor's interface MACs and a is not an address the router holds. Hosts
// on a routed subnet (a VLAN, a VPN) reach the captured LAN under the
// router's MAC, which must not make them the router.
func (n *localNets) forwarded(mac string, a netip.Addr) bool {
	a = a.Unmap()
	n.mu.RLock()
	defer n.mu.RUnlock()
	router := false
	for _, macs := range n.own {
		addrs, ok := macs[mac]
		if !ok {
			continue
		}
		router = true
		if slices.Contains(addrs, a) {
			return false
		}
	}
	return router
}

func (n *localNets) isLocal(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range defaultLocal {
		if p.Contains(a) {
			return true
		}
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, ps := range n.prefixes {
		for _, p := range ps {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// isBroadcast reports a subnet broadcast address of a sensor prefix. With
// no prefix covering the address (an imported capture), a private address
// ending in .255 is taken to be one: a /24 LAN's broadcast.
func (n *localNets) isBroadcast(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	covered := false
	for _, ps := range n.prefixes {
		for _, p := range ps {
			if p.Addr().Is4() && p.Bits() < 31 && p.Contains(a) {
				b := p.Addr().As4()
				host := uint32(1)<<(32-p.Bits()) - 1
				v := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) | host
				if netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}) == a {
					return true
				}
				covered = true
			}
		}
	}
	return !covered && a.IsPrivate() && a.As4()[3] == 255
}

func (s *Store) loadSensors(ctx context.Context) error {
	rows, err := s.r.QueryContext(ctx, `SELECT name, hello FROM sensors`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, hello string
		if err := rows.Scan(&name, &hello); err != nil {
			return err
		}
		var h wire.Hello
		if json.Unmarshal([]byte(hello), &h) == nil {
			s.nets.addHello(name, &h)
		}
	}
	return rows.Err()
}
