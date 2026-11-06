package blocklist

import (
	"net/netip"
	"strings"
)

// Matcher is an immutable snapshot of enabled blocklist entries. Build one
// per evaluation, or keep one cached until entries change.
type Matcher struct {
	domains map[string]Entry
	hosts   map[string]Entry
	ips     []ipRange
}

type ipRange struct {
	lo, hi netip.Addr
	entry  Entry
}

// New builds a matcher from entries.
func New(entries []Entry) *Matcher {
	m := &Matcher{domains: map[string]Entry{}, hosts: map[string]Entry{}}
	for _, e := range entries {
		m.Add(e)
	}
	return m
}

// Add inserts one entry. Invalid values are ignored.
func (m *Matcher) Add(e Entry) {
	switch e.Kind {
	case "domain":
		if v, ok := normalizeDomain(e.Value); ok {
			m.domains[v] = e
		}
	case "host":
		if v, ok := normalizeDomain(e.Value); ok {
			m.hosts[v] = e
		}
	case "ip":
		if r, ok := parseRange(e.Value); ok {
			r.entry = e
			m.ips = append(m.ips, r)
		}
	}
}

// Len reports how many entries the matcher holds.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.domains) + len(m.hosts) + len(m.ips)
}

// MatchName returns the first enabled entry that blocks a name. A host entry
// is exact; a domain entry also covers its subdomains.
func (m *Matcher) MatchName(name string) (Entry, bool) {
	if m == nil {
		return Entry{}, false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return Entry{}, false
	}
	if e, ok := m.hosts[name]; ok {
		return e, true
	}
	if e, ok := m.domains[name]; ok {
		return e, true
	}
	for i := 0; i < len(name); i++ {
		if name[i] != '.' {
			continue
		}
		if e, ok := m.domains[name[i+1:]]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

// MatchIP returns the first entry that blocks an address.
func (m *Matcher) MatchIP(ip string) (Entry, bool) {
	if m == nil {
		return Entry{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return Entry{}, false
	}
	a = a.Unmap()
	for _, r := range m.ips {
		if a.Compare(r.lo) >= 0 && a.Compare(r.hi) <= 0 {
			return r.entry, true
		}
	}
	return Entry{}, false
}

func parseRange(s string) (ipRange, bool) {
	if a, b, ok := strings.Cut(s, "-"); ok {
		lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() || lo.Compare(hi) > 0 {
			return ipRange{}, false
		}
		return ipRange{lo: lo.Unmap(), hi: hi.Unmap()}, true
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return ipRange{}, false
		}
		p = p.Masked()
		return ipRange{lo: p.Addr().Unmap(), hi: lastAddr(p)}, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ipRange{}, false
	}
	a = a.Unmap()
	return ipRange{lo: a, hi: a}, true
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().Unmap()
	bits := p.Bits()
	if a.Is4() {
		v := a.As4()
		for i := 0; i < 4; i++ {
			host := 32 - bits - (3-i)*8
			if host <= 0 {
				continue
			}
			if host > 8 {
				host = 8
			}
			v[i] |= byte((1 << host) - 1)
		}
		return netip.AddrFrom4(v)
	}
	v := a.As16()
	for i := 0; i < 16; i++ {
		host := 128 - bits - (15-i)*8
		if host <= 0 {
			break
		}
		if host > 8 {
			host = 8
		}
		v[i] |= byte((1 << host) - 1)
	}
	return netip.AddrFrom16(v)
}
