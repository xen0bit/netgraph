package policy

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/xen0bit/netgraph/internal/graph"
)

// Seen is one connection a device took part in, as learning needs it.
type Seen struct {
	Direction string // out, in, local
	Name      string // the remote end's best name
	IP        string // the remote end's address
	Port      string // the port served
	Proto     string
	Bytes     uint64
}

// Learned is a least-privilege proposal drawn from what a device did.
type Learned struct {
	Device      string   `json:"device"`
	FromMS      int64    `json:"from"`
	ToMS        int64    `json:"to"`
	Connections int      `json:"connections"`
	Policy      *Policy  `json:"policy"`
	Gaps        []string `json:"gaps,omitempty"`
}

// MaxLearnedRules bounds a learned policy. A device talking to more than this is either a
// server or a browser, and a list of addresses isn't what least privilege means for it.
const MaxLearnedRules = 200

// Learn writes the least a device needs: what it was seen doing is allowed and the rest is
// denied. It's a proposal drawn from what happened to be observed, so a yearly update or a
// backup that didn't run in the window isn't in it, and gaps says what else to check.
func Learn(device string, seen []Seen) (*Policy, []string) {
	const zone = "this"
	p := &Policy{
		Version:  1,
		Zones:    []Zone{{Name: zone, Devices: []string{device}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		Rules:    []Rule{},
		DNS:      DNS{Block: []string{}, Allow: []string{}},
	}
	type key struct{ from, to, port string }
	type group struct {
		key
		bytes uint64
		conns int
	}
	groups := map[key]*group{}
	var gaps []string
	for _, s := range seen {
		// ICMP has no port to name. Anything else with none says nothing a rule could use.
		port := ""
		if s.Proto != "icmp" && s.Proto != "icmpv6" {
			if s.Port == "" || s.Port == "0" {
				continue
			}
			port = s.Port + "/" + strings.ToLower(s.Proto)
		}
		k := key{port: port}
		switch s.Direction {
		case "in":
			// Whoever comes in, it's the service that's being allowed: outside addresses
			// come and go, and a list of them wouldn't describe what the device does.
			k.from, k.to = "any", "zone:"+zone
		case "out", "local":
			k.from, k.to = "zone:"+zone, remoteSelector(s.Name, s.IP)
		default:
			continue
		}
		if k.to == "" {
			continue
		}
		g := groups[k]
		if g == nil {
			g = &group{key: k}
			groups[k] = g
		}
		g.bytes += s.Bytes
		g.conns++
	}
	list := make([]*group, 0, len(groups))
	for _, g := range groups {
		list = append(list, g)
	}
	// Most used first, and the same every time for the same traffic.
	slices.SortFunc(list, func(a, b *group) int {
		return cmp.Or(cmp.Compare(b.bytes, a.bytes), cmp.Compare(b.conns, a.conns), cmp.Compare(a.to, b.to), cmp.Compare(a.from, b.from), cmp.Compare(a.port, b.port))
	})
	if len(list) > MaxLearnedRules {
		gaps = append(gaps, fmt.Sprintf("it did %d different things, and only the %d most used are here: least privilege may not suit a device this varied", len(list), MaxLearnedRules))
		list = list[:MaxLearnedRules]
	}
	for _, g := range list {
		r := Rule{From: g.from, To: g.to, Action: "allow", Ports: []string{}}
		what := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(g.to, "site:"), "ip:"), "domain:")
		if g.from == "any" {
			r.Name = "serves " + g.port
		} else {
			r.Name = "reaches " + what
			if g.port != "" {
				r.Name += " " + g.port
			}
		}
		if g.port != "" {
			r.Ports = []string{g.port}
		}
		p.Rules = append(p.Rules, r)
	}
	return p, gaps
}

// remoteSelector picks what to name the far end by: its site, which survives its addresses
// changing, and failing that the address.
func remoteSelector(name, ip string) string {
	if name != "" && name != ip {
		if _, err := netip.ParseAddr(name); err != nil {
			if site := graph.Site(name); site != "" && checkGlob(site) == nil {
				return "site:" + site
			}
		}
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		return "ip:" + a.String()
	}
	return ""
}
