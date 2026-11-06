package policy

import (
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
)

// Actions a version 2 rule can return. "ask" is a request for a decision; it
// is not a silent denial, and a passive server records it as "would ask".
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionAsk   = "ask"
)

// Rule priorities. Extra-high rules are how an identity failure or a
// protected deny outranks everything else.
const (
	PriorityRegular   = "regular"
	PriorityHigh      = "high"
	PriorityExtraHigh = "extra-high"
)

// Selector is one side of a version 2 rule. Type is a small closed
// vocabulary, and Values are globs, zones, prefixes or class names.
type Selector struct {
	Type   string   `json:"type"`
	Values []string `json:"values,omitempty"`
}

// RuleV2 is a durable, precedence-ordered rule. Local selects the device
// here; Remote selects the far end. Profile empty means all profiles.
type RuleV2 struct {
	ID              string   `json:"id,omitempty"`
	Name            string   `json:"name"`
	Notes           string   `json:"notes,omitempty"`
	Origin          string   `json:"origin,omitempty"` // user, learned, blocklist, factory, remote, agent
	Action          string   `json:"action"`           // allow, deny, ask
	Direction       string   `json:"direction,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	Enabled         *bool    `json:"enabled,omitempty"`
	Protected       bool     `json:"protected,omitempty"`
	Profile         string   `json:"profile,omitempty"`
	Group           string   `json:"group,omitempty"`
	Local           Selector `json:"local"`
	Remote          Selector `json:"remote"`
	Via             Selector `json:"via,omitempty"`
	Ports           []string `json:"ports,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	Lifetime        string   `json:"lifetime,omitempty"` // permanent, temporary, session
	Expiry          int64    `json:"expiry,omitempty"`   // unix ms
	RequiresTrusted bool     `json:"requires_trusted,omitempty"`
	CodeRequirement string   `json:"code_requirement,omitempty"`
}

// EnabledValue reports whether the rule is enabled; an omitted field means
// yes, so a hand-written rule needs no extra ceremony.
func (r RuleV2) EnabledValue() bool {
	return r.Enabled == nil || *r.Enabled
}

func (r *RuleV2) normalize() {
	if r.Direction == "" {
		r.Direction = "both"
	}
	if r.Priority == "" {
		r.Priority = PriorityRegular
	}
	if r.Local.Type == "" {
		r.Local.Type = "any"
	}
	if r.Remote.Type == "" {
		r.Remote.Type = "any"
	}
	if r.Protocol == "" {
		r.Protocol = "any"
	}
	if r.Lifetime == "" {
		r.Lifetime = "permanent"
	}
	if r.Origin == "" {
		r.Origin = "user"
	}
}

const maxRulesV2 = 10000

var localTypes = map[string]bool{
	"any": true, "zone": true, "device": true, "label": true,
	"role": true, "app": true, "process": true, "owner": true,
}

var remoteTypes = map[string]bool{
	"any": true, "ip": true, "host": true, "domain": true, "dns": true,
	"broadcast": true, "multicast": true, "bonjour": true, "local": true,
}

func (p *Policy) validateRulesV2(zones map[string]bool) error {
	for i := range p.RulesV2 {
		r := &p.RulesV2[i]
		r.normalize()
		if r.Name == "" {
			r.Name = fmt.Sprintf("rule %d", i+1)
		}
		switch r.Action {
		case ActionAllow, ActionDeny, ActionAsk:
		default:
			return fmt.Errorf("rule %q action %q is not allow, deny or ask", r.Name, r.Action)
		}
		switch r.Direction {
		case "both", "in", "out", "local":
		default:
			return fmt.Errorf("rule %q direction %q is not in, out, both or local", r.Name, r.Direction)
		}
		switch r.Priority {
		case PriorityRegular, PriorityHigh, PriorityExtraHigh:
		default:
			return fmt.Errorf("rule %q priority %q is not regular, high or extra-high", r.Name, r.Priority)
		}
		switch r.Lifetime {
		case "permanent", "temporary", "session":
		default:
			return fmt.Errorf("rule %q lifetime %q is not permanent, temporary or session", r.Name, r.Lifetime)
		}
		if r.Lifetime == "temporary" && r.Expiry <= 0 {
			return fmt.Errorf("rule %q is temporary but has no expiry", r.Name)
		}
		if err := validateSelector(r.Local, localTypes, zones, true); err != nil {
			return fmt.Errorf("rule %q local: %w", r.Name, err)
		}
		if err := validateSelector(r.Remote, remoteTypes, zones, false); err != nil {
			return fmt.Errorf("rule %q remote: %w", r.Name, err)
		}
		if r.Via.Type != "" {
			via := map[string]bool{"any": true, "app": true, "process": true, "label": true}
			if err := validateSelector(r.Via, via, zones, true); err != nil {
				return fmt.Errorf("rule %q via: %w", r.Name, err)
			}
		}
		for _, spec := range r.Ports {
			if _, err := parsePortSpec(spec); err != nil {
				return fmt.Errorf("rule %q: %w", r.Name, err)
			}
		}
		if r.Protocol != "any" && r.Protocol != "" {
			if _, ok := protocolNumber(r.Protocol); !ok {
				return fmt.Errorf("rule %q protocol %q is not a known protocol", r.Name, r.Protocol)
			}
		}
		if r.RequiresTrusted && r.CodeRequirement != "" {
			return fmt.Errorf("rule %q cannot require both a trusted signature and a code requirement", r.Name)
		}
	}
	return nil
}

func validateSelector(s Selector, allowed map[string]bool, zones map[string]bool, local bool) error {
	if s.Type == "" {
		s.Type = "any"
	}
	if !allowed[s.Type] {
		return fmt.Errorf("type %q is not one of %s", s.Type, strings.Join(sortedKeys(allowed), ", "))
	}
	if s.Type == "any" {
		if len(s.Values) > 0 {
			return fmt.Errorf("any takes no values")
		}
		return nil
	}
	if len(s.Values) == 0 {
		return fmt.Errorf("%s needs at least one value", s.Type)
	}
	for _, v := range s.Values {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("empty value")
		}
		switch s.Type {
		case "zone":
			if v != "any" && !zones[v] {
				return fmt.Errorf("no such zone %q", v)
			}
		case "ip":
			if strings.Contains(v, "/") {
				if _, err := netip.ParsePrefix(v); err != nil {
					return fmt.Errorf("bad prefix %q: %w", v, err)
				}
			} else if _, err := netip.ParseAddr(v); err != nil {
				return fmt.Errorf("bad address %q: %w", v, err)
			}
		case "domain", "host", "dns":
			if err := checkGlob(v); err != nil {
				return fmt.Errorf("bad pattern %q: %w", v, err)
			}
			if strings.ContainsAny(v, "/\\") {
				return fmt.Errorf("name %q contains a path separator", v)
			}
		case "broadcast", "multicast", "bonjour", "local", "device", "label", "role", "app", "process", "owner":
			if err := checkGlob(v); err != nil {
				return fmt.Errorf("bad pattern %q: %w", v, err)
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// A deterministic message is worth the tiny sort.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// portSpec is one version 2 port selector. Proto is empty for any.
type portRange struct {
	lo, hi int
	proto  string
}

func parsePortSpec(s string) (portRange, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") || s == "*" {
		return portRange{lo: 0, hi: 65535}, nil
	}
	port, proto, _ := strings.Cut(s, "/")
	port, proto = strings.TrimSpace(port), strings.ToLower(strings.TrimSpace(proto))
	if proto != "" {
		if _, ok := protocolNumber(proto); !ok {
			return portRange{}, fmt.Errorf("port %q: unknown protocol %q", s, proto)
		}
	}
	lo, hi := port, port
	if a, b, ok := strings.Cut(port, "-"); ok {
		lo, hi = strings.TrimSpace(a), strings.TrimSpace(b)
	}
	l, err := strconv.Atoi(lo)
	if err != nil || l < 0 || l > 65535 {
		return portRange{}, fmt.Errorf("port %q: want NUMBER or NUMBER-NUMBER[/PROTO]", s)
	}
	h, err := strconv.Atoi(hi)
	if err != nil || h < 0 || h > 65535 || h < l {
		return portRange{}, fmt.Errorf("port %q: bad range", s)
	}
	return portRange{lo: l, hi: h, proto: proto}, nil
}

// protocolNumber maps the protocol names rules can use. Numeric strings are
// accepted so an unusual protocol does not need a named entry.
func protocolNumber(s string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "icmpv6":
		return 58, true
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 255 {
		return n, true
	}
	return 0, false
}

func globName(pat, s string) bool {
	if pat == "" || s == "" {
		return false
	}
	ok, err := path.Match(strings.ToLower(pat), strings.ToLower(s))
	return err == nil && ok
}

// Summary is a policy without its rules, for list views.
type Summary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Mode     string `json:"mode"`
	Active   bool   `json:"active"`
	Rules    int    `json:"rules"`
	Notes    string `json:"notes,omitempty"`
	Created  int64  `json:"created"`
	Modified int64  `json:"modified"`
}
