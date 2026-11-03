// Package policy implements the read-only what-if policy model. It is a
// deliberately small, first-match rule language; it never touches a
// firewall and never claims that observed traffic is complete.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/graph"
)

type Policy struct {
	Version  int      `json:"version"`
	Zones    []Zone   `json:"zones"`
	Defaults Defaults `json:"defaults"`
	Rules    []Rule   `json:"rules"`
	DNS      DNS      `json:"dns"`
}

type Zone struct {
	Name    string   `json:"name"`
	Devices []string `json:"devices"`
}

type Defaults struct {
	Egress    string `json:"egress"`     // allow | deny
	Ingress   string `json:"ingress"`    // allow | deny
	IntraZone string `json:"intra_zone"` // allow | deny
	DNS       string `json:"dns"`        // allow | deny
}

type Rule struct {
	Name   string   `json:"name"`
	From   string   `json:"from"`
	To     string   `json:"to"`
	Ports  []string `json:"ports"`
	Action string   `json:"action"` // allow | deny
}

type DNS struct {
	Block []string `json:"block"`
	Allow []string `json:"allow"`
}

func Parse(r io.Reader) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) Validate() error {
	if p.Version != 0 && p.Version != 1 {
		return fmt.Errorf("policy version %d is not supported", p.Version)
	}
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Defaults.Egress == "" {
		p.Defaults.Egress = "deny"
	}
	if p.Defaults.Ingress == "" {
		p.Defaults.Ingress = "deny"
	}
	if p.Defaults.IntraZone == "" {
		p.Defaults.IntraZone = "allow"
	}
	if p.Defaults.DNS == "" {
		p.Defaults.DNS = "allow"
	}
	for _, d := range []string{p.Defaults.Egress, p.Defaults.Ingress, p.Defaults.IntraZone, p.Defaults.DNS} {
		if d != "allow" && d != "deny" {
			return fmt.Errorf("default %q is not allow or deny", d)
		}
	}
	seen := map[string]bool{}
	for _, z := range p.Zones {
		if z.Name == "" || seen[z.Name] {
			return fmt.Errorf("duplicate or empty zone name %q", z.Name)
		}
		seen[z.Name] = true
	}
	for _, r := range p.Rules {
		if r.From == "" || r.To == "" {
			return fmt.Errorf("rule %q needs from and to", r.Name)
		}
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("rule %q action %q is not allow or deny", r.Name, r.Action)
		}
		for _, port := range r.Ports {
			if _, _, err := parsePort(port); err != nil {
				return fmt.Errorf("rule %q: %w", r.Name, err)
			}
		}
	}
	if len(p.Rules) > 10000 {
		return fmt.Errorf("too many rules (%d)", len(p.Rules))
	}
	return nil
}

func (p *Policy) Hash() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// ZoneFor returns the first zone matching a device, or "" for unknown.
func (p *Policy) ZoneFor(id, label, role string) string {
	for _, z := range p.Zones {
		for _, pat := range z.Devices {
			if matchDevice(pat, id, label, role) {
				return z.Name
			}
		}
	}
	return ""
}

func matchDevice(pat, id, label, role string) bool {
	switch {
	case pat == "any" || pat == "*":
		return true
	case strings.HasPrefix(pat, "device:"):
		return id == pat
	case strings.HasPrefix(pat, "label:"):
		return glob(pat[len("label:"):], label)
	case strings.HasPrefix(pat, "role:"):
		return strings.EqualFold(pat[len("role:"):], role)
	case strings.HasPrefix(pat, "ssid:"):
		return false // no SSID in a flow; keep the selector honest
	default:
		return glob(pat, label) || glob(pat, id)
	}
}

// Decide returns the first matching rule and whether it allows the flow.
func (p *Policy) Decide(zone, direction, name, ip, port, proto string, asn uint32, country string) (rule string, allow bool, matched bool) {
	if direction == "external" {
		return "", false, false
	}
	for _, r := range p.Rules {
		if !fromMatches(r.From, zone) {
			continue
		}
		if !toMatches(r.To, name, ip, asn, country) {
			continue
		}
		if !portsMatch(r.Ports, port, proto) {
			continue
		}
		return r.Name, r.Action == "allow", true
	}
	// Defaults depend on direction and whether both ends are in one zone.
	switch direction {
	case "out":
		return "", p.Defaults.Egress == "allow", false
	case "in":
		return "", p.Defaults.Ingress == "allow", false
	case "local":
		return "", p.Defaults.IntraZone == "allow", false
	}
	return "", true, false
}

func fromMatches(from, zone string) bool {
	from = strings.TrimSpace(from)
	if from == "any" || from == "zone:any" || from == "*" {
		return true
	}
	return from == "zone:"+zone
}

func toMatches(to, name, ip string, asn uint32, country string) bool {
	to = strings.TrimSpace(to)
	switch {
	case to == "any" || to == "*":
		return true
	case strings.HasPrefix(to, "site:"):
		site := graph.Site(name)
		return site != "" && glob(to[len("site:"):], site)
	case strings.HasPrefix(to, "domain:"):
		return glob(to[len("domain:"):], name)
	case strings.HasPrefix(to, "ip:"):
		pat := to[len("ip:"):]
		if strings.Contains(pat, "/") {
			p, err := netip.ParsePrefix(pat)
			a, aerr := netip.ParseAddr(ip)
			return err == nil && aerr == nil && p.Contains(a)
		}
		return ip == pat
	case strings.HasPrefix(to, "asn:"):
		n, err := strconv.ParseUint(strings.TrimPrefix(to[len("asn:"):], "AS"), 10, 32)
		return err == nil && uint32(n) == asn
	case strings.HasPrefix(to, "country:"):
		return strings.EqualFold(to[len("country:"):], country)
	}
	return glob(to, name) || glob(to, ip)
}

func portsMatch(ports []string, port, proto string) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		pp, pr, err := parsePort(p)
		if err != nil {
			continue
		}
		if pp == port && (pr == "" || pr == proto) {
			return true
		}
	}
	return false
}

func parsePort(s string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty port")
	}
	if p, pr, ok := strings.Cut(s, "/"); ok {
		return strings.TrimSpace(p), strings.ToLower(strings.TrimSpace(pr)), nil
	}
	return s, "", nil
}

// DNSBlocked reports whether a name is blocked and not explicitly allowed.
func (p *Policy) DNSBlocked(name string) bool {
	for _, a := range p.DNS.Allow {
		if glob(a, name) {
			return false
		}
	}
	for _, b := range p.DNS.Block {
		if glob(b, name) {
			return true
		}
	}
	return p.Defaults.DNS == "deny"
}

func glob(pat, s string) bool {
	if pat == "" {
		return false
	}
	if pat == "*" || pat == "any" {
		return true
	}
	ok, err := path.Match(strings.ToLower(pat), strings.ToLower(s))
	return err == nil && ok
}
