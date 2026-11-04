package policy

import (
	"encoding/xml"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Export turns a policy into a firewall's configuration, for a person to read and apply.
// netgraph never touches a firewall itself.
//
// Everything that reaches the output has been parsed or reduced to a safe alphabet, because
// labels and names come from the network, and a hostname mustn't be able to add a rule. A
// firewall works in addresses, so a selector naming a site, network or country uses the ones
// seen for it, and says so. What can't be expressed is commented out and warned about: a
// dropped deny would be a hole, so it must never be silent.

// Export formats.
const (
	FormatNftables = "nftables"
	FormatOpenWrt  = "openwrt"
	FormatOPNsense = "opnsense"
)

// ValidFormat says whether this can export to a format.
func ValidFormat(f string) bool {
	return f == FormatNftables || f == FormatOpenWrt || f == FormatOPNsense
}

// ObservedDevice is a device here, as far as zones need to know.
type ObservedDevice struct {
	ID, Label, Role string
	IPs             []string
}

// ObservedRemote is a far end seen in traffic.
type ObservedRemote struct {
	Name, IP string
	ASN      uint32
	Country  string
}

// Observed is what the export resolves names to addresses from.
type Observed struct {
	Devices []ObservedDevice
	Remotes []ObservedRemote
}

// Exported is a generated configuration.
type Exported struct {
	Format   string   `json:"format"`
	Filename string   `json:"filename"`
	Config   string   `json:"config"`
	Warnings []string `json:"warnings,omitempty"`
}

// Bounds on what one export can generate.
const (
	maxSetAddresses  = 4096
	maxExpandedRules = 5000 // OPNsense has no inline sets, so rules multiply
)

type addrSet struct {
	any    bool
	v4, v6 []string
}

func (s *addrSet) add(addr string) {
	if p, err := netip.ParsePrefix(addr); err == nil {
		if p.Addr().Is4() {
			s.v4 = append(s.v4, p.Masked().String())
		} else {
			s.v6 = append(s.v6, p.Masked().String())
		}
		return
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return // only what parses as an address gets through
	}
	a = a.Unmap()
	// None of these name a host a firewall could filter for: 0.0.0.0 is a client before DHCP,
	// and a link-local address never crosses a router.
	if a.Zone() != "" || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsLoopback() {
		return
	}
	if a.Is4() {
		s.v4 = append(s.v4, a.String())
	} else {
		s.v6 = append(s.v6, a.String())
	}
}

func (s *addrSet) finish() (truncated bool) {
	for _, list := range []*[]string{&s.v4, &s.v6} {
		slices.Sort(*list)
		*list = slices.Compact(*list)
		if len(*list) > maxSetAddresses {
			*list = (*list)[:maxSetAddresses]
			truncated = true
		}
	}
	return truncated
}

func (s *addrSet) empty() bool { return !s.any && len(s.v4) == 0 && len(s.v6) == 0 }

func (s *addrSet) merge(o addrSet) {
	s.v4 = append(s.v4, o.v4...)
	s.v6 = append(s.v6, o.v6...)
	s.any = s.any || o.any
}

type portSpec struct {
	port  string // empty for any
	proto string // tcp, udp, or empty for any
}

// planRule is a rule reduced to what a firewall can say.
type planRule struct {
	name    string
	allow   bool
	src     addrSet
	dst     addrSet
	ports   []portSpec
	note    string // why this came out as it did
	skipped string // set if it can't be expressed
}

type plan struct {
	rules    []planRule
	warnings []string
}

func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '.', r == '-', r == '_', r == ':', r == '/':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 60 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// ports reads a rule's list. Validate has already seen them, and parsePort returns only
// digits and a lowered protocol, of which only tcp and udp reach the output.
func ports(list []string) ([]portSpec, string) {
	if len(list) == 0 {
		return []portSpec{{}}, ""
	}
	var out []portSpec
	for _, p := range list {
		port, proto, err := parsePort(p)
		if err != nil {
			return nil, "a port doesn't parse"
		}
		switch proto {
		case "tcp", "udp":
			out = append(out, portSpec{port, proto})
		case "":
			out = append(out, portSpec{port, "tcp"}, portSpec{port, "udp"})
		default:
			return nil, "a port names a protocol other than tcp or udp"
		}
	}
	return out, ""
}

// compile reduces a policy to rules over addresses: its rules in order, then its defaults.
func compile(p *Policy, obs Observed) plan {
	var out plan
	warn := func(format string, a ...any) { out.warnings = append(out.warnings, fmt.Sprintf(format, a...)) }
	zones := map[string]*addrSet{}
	allZones := addrSet{}
	members := map[string]int{}
	for _, d := range obs.Devices {
		zone := p.ZoneFor(d.ID, d.Label, d.Role)
		if zone == "" {
			continue
		}
		set := zones[zone]
		if set == nil {
			set = &addrSet{}
			zones[zone] = set
		}
		members[zone]++
		for _, ip := range d.IPs {
			set.add(ip)
		}
	}
	for _, z := range p.Zones {
		set := zones[z.Name]
		if set == nil {
			set = &addrSet{}
			zones[z.Name] = set
		}
		if set.finish() {
			warn("zone %q has more addresses than this exports", safe(z.Name))
		}
		if members[z.Name] == 0 {
			warn("zone %q matches no device seen in this window", safe(z.Name))
		} else if set.empty() {
			warn("zone %q has devices but no address seen for them", safe(z.Name))
		}
		allZones.merge(*set)
	}
	allZones.finish()
	resolved := false
	resolve := func(sel string) (addrSet, string) {
		sel = strings.TrimSpace(sel)
		var set addrSet
		switch {
		case sel == "any" || sel == "*":
			set.any = true
			return set, ""
		case sel == "zone:any":
			return allZones, ""
		case strings.HasPrefix(sel, "zone:"):
			if z := zones[sel[len("zone:"):]]; z != nil {
				return *z, ""
			}
			return set, ""
		case strings.HasPrefix(sel, "ip:"):
			set.add(sel[len("ip:"):])
			return set, ""
		}
		if a, err := netip.ParseAddr(sel); err == nil {
			set.add(a.String())
			return set, ""
		}
		resolved = true
		for _, r := range obs.Remotes {
			e := endpoint{name: r.Name, ip: r.IP, asn: r.ASN, country: r.Country}
			if e.matches(sel) {
				set.add(r.IP)
			}
		}
		if set.finish() {
			warn("selector %q matched more addresses than this exports", safe(sel))
		}
		return set, "the addresses seen for " + safe(sel)
	}
	for _, r := range p.Rules {
		pr := planRule{name: safe(r.Name), allow: r.Action == "allow"}
		if pr.name == "" {
			pr.name = "unnamed"
		}
		var srcNote, dstNote string
		pr.src, srcNote = resolve(r.From)
		pr.dst, dstNote = resolve(r.To)
		pr.note = strings.Join(slices.DeleteFunc([]string{srcNote, dstNote}, func(s string) bool { return s == "" }), ", ")
		ps, bad := ports(r.Ports)
		pr.ports = ps
		switch {
		case bad != "":
			pr.skipped = bad
		case pr.src.empty():
			pr.skipped = "nothing was seen for " + safe(r.From)
		case pr.dst.empty():
			pr.skipped = "nothing was seen for " + safe(r.To)
		}
		if pr.skipped != "" {
			if pr.allow {
				warn("rule %q is left out because %s: what it allows falls through to what follows", pr.name, pr.skipped)
			} else {
				warn("rule %q is left out because %s: WHAT IT DENIES IS NOT DENIED by this export", pr.name, pr.skipped)
			}
		}
		out.rules = append(out.rules, pr)
	}
	if resolved {
		warn("a firewall can't match names: rules naming a site, domain, network or country use the addresses seen in this window. Those change, and addresses not seen aren't covered")
	}
	if len(p.DNS.Block) > 0 || len(p.DNS.Allow) > 0 || p.Defaults.DNS == "deny" {
		warn("DNS rules aren't exported: a firewall can't block a name. Put them on your DNS server")
	}
	// The defaults, for devices in zones only: what-if calls anything else unknown, and so
	// this leaves it alone. Within a zone first, since leaving it is the wider case.
	for _, z := range p.Zones {
		if set := zones[z.Name]; !set.empty() {
			out.rules = append(out.rules, planRule{name: "within " + safe(z.Name), allow: p.Defaults.IntraZone == "allow", src: *set, dst: *set, ports: []portSpec{{}}})
		}
	}
	anyAddr := addrSet{any: true}
	if !allZones.empty() {
		out.rules = append(out.rules,
			planRule{name: "default leaving zones", allow: p.Defaults.Egress == "allow", src: allZones, dst: anyAddr, ports: []portSpec{{}}},
			planRule{name: "default entering zones", allow: p.Defaults.Ingress == "allow", src: anyAddr, dst: allZones, ports: []portSpec{{}}},
		)
	}
	return out
}

// ExportPolicy generates a firewall's configuration for a policy.
func ExportPolicy(p *Policy, format string, obs Observed, stamp string) (*Exported, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	pl := compile(p, obs)
	header := []string{
		"Generated by netgraph from what-if policy " + safe(p.Hash()) + ", on " + safe(stamp) + ".",
		"Nothing has been applied. Read it, test it, keep a way back in, and apply it yourself.",
		"Devices are matched by the addresses seen for them, so give them fixed leases first.",
		"Traffic to or from the router itself isn't touched, and devices in no zone aren't either.",
		"Two devices on the same LAN talk through its switch, which a router's firewall never sees.",
	}
	var cfg, name string
	switch format {
	case FormatNftables:
		cfg, name = nftables(pl, header), "netgraph.nft"
	case FormatOpenWrt:
		cfg, name = openwrt(pl, header), "netgraph-firewall.uci"
	case FormatOPNsense:
		var more []string
		cfg, more = opnsense(pl, header)
		name = "netgraph-filter.xml"
		pl.warnings = append(pl.warnings, more...)
	default:
		return nil, fmt.Errorf("format %q is not nftables, openwrt or opnsense", format)
	}
	return &Exported{Format: format, Filename: name, Config: cfg, Warnings: pl.warnings}, nil
}

func nftAddrs(list []string) string {
	if len(list) == 1 {
		return list[0]
	}
	return "{ " + strings.Join(list, ", ") + " }"
}

// families lists the address families a rule applies to, with the address lists for each.
// Empty family means no address match is needed at all.
func families(r planRule) []struct {
	family   string
	src, dst []string
} {
	type f = struct {
		family   string
		src, dst []string
	}
	if r.src.any && r.dst.any {
		return []f{{}}
	}
	var out []f
	if (r.src.any || len(r.src.v4) > 0) && (r.dst.any || len(r.dst.v4) > 0) {
		out = append(out, f{"ip", r.src.v4, r.dst.v4})
	}
	if (r.src.any || len(r.src.v6) > 0) && (r.dst.any || len(r.dst.v6) > 0) {
		out = append(out, f{"ip6", r.src.v6, r.dst.v6})
	}
	return out
}

func nftables(pl plan, header []string) string {
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	for _, h := range header {
		b.WriteString("# " + h + "\n")
	}
	b.WriteString(`
table inet netgraph
delete table inet netgraph

table inet netgraph {
	chain forward {
		# Before the system's own rules. "accept" here still leaves them to decide;
		# "drop" is final.
		type filter hook forward priority filter - 10; policy accept;
		ct state established,related accept
`)
	for _, r := range pl.rules {
		b.WriteString("\n		# " + r.name + "\n")
		if r.note != "" {
			b.WriteString("		# uses " + r.note + "\n")
		}
		if r.skipped != "" {
			b.WriteString("		# LEFT OUT: " + r.skipped + "\n")
			continue
		}
		verdict := "drop"
		if r.allow {
			verdict = "accept"
		}
		fams := families(r)
		if len(fams) == 0 {
			b.WriteString("		# LEFT OUT: its two sides have no address family in common\n")
			continue
		}
		for _, fam := range fams {
			for _, p := range r.ports {
				var m []string
				if fam.family != "" {
					if len(fam.src) > 0 {
						m = append(m, fam.family+" saddr "+nftAddrs(fam.src))
					}
					if len(fam.dst) > 0 {
						m = append(m, fam.family+" daddr "+nftAddrs(fam.dst))
					}
				}
				if p.port != "" {
					m = append(m, p.proto+" dport "+p.port)
				}
				m = append(m, verdict)
				b.WriteString("		" + strings.Join(m, " ") + "\n")
			}
		}
	}
	b.WriteString("	}\n}\n")
	return b.String()
}

func openwrt(pl plan, header []string) string {
	var b strings.Builder
	for _, h := range header {
		b.WriteString("# " + h + "\n")
	}
	b.WriteString("#\n# For /etc/config/firewall, ahead of your other rules. These match by address, whatever the\n# firewall zone, and fw4 keeps their order.\n")
	n := 0
	for _, r := range pl.rules {
		b.WriteString("\n# " + r.name + "\n")
		if r.note != "" {
			b.WriteString("# uses " + r.note + "\n")
		}
		if r.skipped != "" {
			b.WriteString("# LEFT OUT: " + r.skipped + "\n")
			continue
		}
		target := "DROP"
		if r.allow {
			target = "ACCEPT"
		}
		for _, fam := range families(r) {
			family := map[string]string{"ip": "ipv4", "ip6": "ipv6", "": "any"}[fam.family]
			// One rule per protocol: fw4 would otherwise apply every port to every protocol.
			byProto := map[string][]string{}
			var order []string
			for _, p := range r.ports {
				if _, ok := byProto[p.proto]; !ok {
					order = append(order, p.proto)
				}
				if p.port != "" {
					byProto[p.proto] = append(byProto[p.proto], p.port)
				}
			}
			for _, proto := range order {
				n++
				fmt.Fprintf(&b, "config rule\n	option name 'netgraph %d %s'\n	option src '*'\n	option dest '*'\n	option family '%s'\n	option target '%s'\n", n, r.name, family, target)
				if proto == "" {
					b.WriteString("	option proto 'all'\n")
				} else {
					b.WriteString("	option proto '" + proto + "'\n")
				}
				for _, a := range fam.src {
					b.WriteString("	list src_ip '" + a + "'\n")
				}
				for _, a := range fam.dst {
					b.WriteString("	list dest_ip '" + a + "'\n")
				}
				for _, p := range byProto[proto] {
					b.WriteString("	list dest_port '" + p + "'\n")
				}
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

// xmlComment makes text safe inside a comment, where escaping doesn't work and "--" ends it.
func xmlComment(s string) string {
	return strings.ReplaceAll(s, "-", "_")
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// opnsense writes the filter section of its config.xml. It has no inline address lists, so
// rules multiply out, which is why this is bounded.
func opnsense(pl plan, header []string) (string, []string) {
	var warnings []string
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n<!--\n")
	for _, h := range header {
		b.WriteString("  " + xmlComment(h) + "\n")
	}
	b.WriteString("  For System: Configuration: Backups, restoring the Firewall Rules area. Rules are for the LAN interface.\n-->\n<filter>\n")
	count := 0
	full := false
	endpoint := func(tag string, list []string, port string) string {
		var e strings.Builder
		e.WriteString("      <" + tag + ">\n")
		if len(list) == 0 {
			e.WriteString("        <any>1</any>\n")
		} else {
			e.WriteString("        <address>" + xmlText(list[0]) + "</address>\n")
		}
		if port != "" {
			e.WriteString("        <port>" + port + "</port>\n")
		}
		e.WriteString("      </" + tag + ">\n")
		return e.String()
	}
	for _, r := range pl.rules {
		if r.skipped != "" {
			b.WriteString("  <!-- " + xmlComment(r.name) + " LEFT OUT: " + xmlComment(r.skipped) + " -->\n")
			continue
		}
		kind := "block"
		if r.allow {
			kind = "pass"
		}
		for _, fam := range families(r) {
			inet := map[string]string{"ip": "inet", "ip6": "inet6", "": "inet46"}[fam.family]
			srcs, dsts := expand(fam.src), expand(fam.dst)
			for _, s := range srcs {
				for _, d := range dsts {
					for _, p := range r.ports {
						if count >= maxExpandedRules {
							full = true
							continue
						}
						count++
						proto := p.proto
						if proto == "" {
							proto = "any"
						}
						b.WriteString("  <rule>\n    <type>" + kind + "</type>\n    <interface>lan</interface>\n    <direction>in</direction>\n    <quick>1</quick>\n    <ipprotocol>" + inet + "</ipprotocol>\n    <protocol>" + proto + "</protocol>\n")
						b.WriteString("    <descr>netgraph " + strconv.Itoa(count) + " " + xmlText(r.name) + "</descr>\n")
						var src, dst []string
						if s != "" {
							src = []string{s}
						}
						if d != "" {
							dst = []string{d}
						}
						b.WriteString(endpoint("source", src, ""))
						b.WriteString(endpoint("destination", dst, p.port))
						b.WriteString("  </rule>\n")
					}
				}
			}
		}
	}
	if full {
		warnings = append(warnings, fmt.Sprintf("it stops at %d rules, so later rules AND DEFAULTS ARE MISSING: use fewer addresses, or a firewall alias", maxExpandedRules))
	}
	b.WriteString("</filter>\n")
	return b.String(), warnings
}

func expand(list []string) []string {
	if len(list) == 0 {
		return []string{""}
	}
	return list
}
