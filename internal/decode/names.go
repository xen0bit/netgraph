package decode

import (
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Answers converts a response's answer section to wire form. SVCB/HTTPS
// address hints become extra entries carrying the record's type and the
// hinted address as data, so correlation can tie a connection to the name
// even when the client never asked for A/AAAA.
func Answers(m *DNSMsg) []wire.Answer {
	var out []wire.Answer
	for i := range m.Answers {
		rr := &m.Answers[i]
		if rr.Type == TypeOPT {
			continue
		}
		t := TypeName(rr.Type)
		out = append(out, wire.Answer{Name: strings.ToLower(rr.Name), Type: t, TTL: rr.TTL, Data: rr.Data()})
		for _, h := range rr.Hints {
			out = append(out, wire.Answer{Name: strings.ToLower(rr.Name), Type: t, TTL: rr.TTL, Data: h.String()})
		}
	}
	return out
}

// MDNS reduces an mDNS packet to what it says about its sender: the .local
// names it holds addresses for, its DNS-SD service instances, and (for
// queries) what it is looking for.
//
// Records are read from every section: responders put A/AAAA/SRV/TXT in the
// additional section as often as in the answers.
func MDNS(m *DNSMsg, src netip.Addr, mac string) *wire.MDNS {
	ev := &wire.MDNS{MAC: mac, IP: src, Response: m.Response}
	if !m.Response {
		for _, q := range m.Questions {
			ev.Queries = append(ev.Queries, strings.ToLower(q.Name))
		}
		// Probes and known-answer queries carry the sender's own records in
		// the authority/answer sections; fall through to read them.
	}
	hosts := map[string]*wire.MDNSHost{} // by lower-cased name
	var order []string
	host := func(name string) *wire.MDNSHost {
		k := strings.ToLower(name)
		h, ok := hosts[k]
		if !ok {
			h = &wire.MDNSHost{Name: name} // keep the first spelling
			hosts[k] = h
			order = append(order, k)
		}
		return h
	}
	svcs := map[string]*wire.Service{}
	svc := func(instance string) *wire.Service {
		k := strings.ToLower(instance)
		s, ok := svcs[k]
		if !ok {
			s = &wire.Service{Instance: instance, Type: serviceType(instance)}
			svcs[k] = s
		}
		return s
	}
	for _, sec := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for i := range sec {
			rr := &sec[i]
			switch rr.Type {
			case TypeA, TypeAAAA:
				if rr.Addr.IsValid() && !strings.Contains(rr.Name, "._") {
					h := host(rr.Name)
					if !slices.Contains(h.Addrs, rr.Addr) {
						h.Addrs = append(h.Addrs, rr.Addr)
					}
				}
			case TypePTR:
				// "<type>.local PTR <instance>" announces an instance; the
				// meta-query PTRs (_services._dns-sd._udp) only list types.
				// A reverse-address PTR names the host holding that address.
				switch {
				case strings.HasSuffix(rr.Name, ".in-addr.arpa") || strings.HasSuffix(rr.Name, ".ip6.arpa"):
					if rr.Target != "" {
						h := host(rr.Target)
						if a, ok := reverseAddr(rr.Name); ok && !slices.Contains(h.Addrs, a) {
							h.Addrs = append(h.Addrs, a)
						}
					}
				case strings.HasPrefix(strings.ToLower(rr.Name), "_services._dns-sd."):
				case rr.Target != "" && strings.Contains(rr.Target, "._"):
					svc(rr.Target)
				}
			case TypeSRV:
				if strings.Contains(rr.Name, "._") {
					s := svc(rr.Name)
					s.Target, s.Port = rr.Target, rr.Port
					if rr.Target != "" {
						host(rr.Target)
					}
				}
			case TypeTXT:
				if strings.Contains(rr.Name, "._") {
					s := svc(rr.Name)
					for _, kv := range rr.TXT {
						k, v, _ := strings.Cut(kv, "=")
						if k == "" || len(s.TXT) >= 32 {
							continue
						}
						if s.TXT == nil {
							s.TXT = map[string]string{}
						}
						s.TXT[strings.ToLower(k)] = v
					}
				}
			}
		}
	}
	sort.Strings(order)
	for _, k := range order {
		h := hosts[k]
		sort.Slice(h.Addrs, func(i, j int) bool { return h.Addrs[i].Less(h.Addrs[j]) })
		ev.Hosts = append(ev.Hosts, *h)
	}
	for _, s := range svcs {
		ev.Services = append(ev.Services, *s)
	}
	sort.Slice(ev.Services, func(i, j int) bool { return ev.Services[i].Instance < ev.Services[j].Instance })
	if len(ev.Hosts) == 0 && len(ev.Services) == 0 && len(ev.Queries) == 0 {
		return nil
	}
	return ev
}

// reverseAddr parses "4.3.2.1.in-addr.arpa" and the nibble form of
// ip6.arpa back into an address.
func reverseAddr(name string) (netip.Addr, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		p := strings.Split(rest, ".")
		if len(p) != 4 {
			return netip.Addr{}, false
		}
		slices.Reverse(p)
		a, err := netip.ParseAddr(strings.Join(p, "."))
		return a, err == nil
	}
	if rest, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		p := strings.Split(rest, ".")
		if len(p) != 32 {
			return netip.Addr{}, false
		}
		slices.Reverse(p)
		var b strings.Builder
		for i, n := range p {
			if i > 0 && i%4 == 0 {
				b.WriteByte(':')
			}
			b.WriteString(n)
		}
		a, err := netip.ParseAddr(b.String())
		return a, err == nil
	}
	return netip.Addr{}, false
}

// serviceType extracts "_airplay._tcp" from "Living Room._airplay._tcp.local".
func serviceType(instance string) string {
	i := strings.Index(instance, "._")
	if i < 0 {
		return ""
	}
	rest := instance[i+1:]
	parts := strings.Split(rest, ".")
	if len(parts) >= 2 {
		return strings.ToLower(parts[0] + "." + parts[1])
	}
	return strings.ToLower(rest)
}

// LLMNR returns the names a host claimed in an LLMNR response: each answer
// for an address is the responder saying "that name is me".
func LLMNR(m *DNSMsg, src netip.Addr, mac string) []wire.Name {
	if !m.Response {
		return nil
	}
	var out []wire.Name
	seen := map[string]bool{}
	for _, rr := range m.Answers {
		if (rr.Type == TypeA || rr.Type == TypeAAAA) && rr.Name != "" && !seen[strings.ToLower(rr.Name)] {
			seen[strings.ToLower(rr.Name)] = true
			out = append(out, wire.Name{MAC: mac, IP: src, Name: strings.ToLower(rr.Name), Proto: "llmnr"})
		}
	}
	return out
}

// NetBIOS name suffixes worth naming (MS-NBTE §2.2.1).
var nbSuffix = map[byte]string{
	0x00: "workstation", 0x03: "messenger", 0x1b: "domain-master-browser",
	0x1c: "domain-controllers", 0x1d: "master-browser", 0x1e: "browser-election", 0x20: "file-server",
}

// NBNS returns the names claimed by NetBIOS name-service registrations,
// refreshes and positive query responses.
func NBNS(m *DNSMsg, src netip.Addr, mac string) []wire.Name {
	var rrs []RR
	switch {
	case !m.Response && (m.Opcode == 5 || m.Opcode == 8 || m.Opcode == 9): // registration, refresh, multi-homed
		rrs = m.Additional
	case m.Response && m.Opcode == 0 && m.RCode == 0:
		rrs = m.Answers
	default:
		return nil
	}
	var out []wire.Name
	for _, rr := range rrs {
		if rr.Type != typeNB {
			continue
		}
		name, suffix, ok := decodeNetBIOSName(rr.Name)
		if !ok || name == "" || name == "*" {
			continue
		}
		ip := src
		group := false
		if len(rr.Raw) >= 6 {
			group = rr.Raw[0]&0x80 != 0
			ip = netip.AddrFrom4([4]byte(rr.Raw[2:6]))
		}
		n := wire.Name{MAC: mac, IP: ip, Name: strings.ToLower(name), Proto: "nbns", Group: group}
		if s, ok := nbSuffix[suffix]; ok {
			n.Suffix = s
		} else {
			n.Suffix = "0x" + strings.ToLower(string("0123456789ABCDEF"[suffix>>4])+string("0123456789ABCDEF"[suffix&0xf]))
		}
		out = append(out, n)
	}
	return out
}

// decodeNetBIOSName undoes first-level encoding (RFC 1001 §14.1): 32
// characters 'A'-'P', each pair one nibble-encoded byte. The 16th byte is the
// suffix; the first 15 are the space-padded name.
func decodeNetBIOSName(dotted string) (string, byte, bool) {
	label, _, _ := strings.Cut(dotted, ".")
	if len(label) != 32 {
		return "", 0, false
	}
	var raw [16]byte
	for i := range 16 {
		hi, lo := label[2*i]-'A', label[2*i+1]-'A'
		if hi > 15 || lo > 15 {
			return "", 0, false
		}
		raw[i] = hi<<4 | lo
	}
	return strings.TrimRight(string(raw[:15]), " \x00"), raw[15], true
}
