// Package policy implements the read-only what-if policy model. It is a
// deliberately small, first-match rule language; it never touches a
// firewall and never claims that observed traffic is complete.
package policy

import (
	"bytes"
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
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Mode     string   `json:"mode,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	Active   bool     `json:"active,omitempty"`
	Created  int64    `json:"created,omitempty"`
	Modified int64    `json:"modified,omitempty"`
	Zones    []Zone   `json:"zones"`
	Defaults Defaults `json:"defaults"`
	// Rules is version 1's first-match rule list. RulesV2 is version 2's
	// precedence list. Only one is populated for a given policy.
	Rules   []Rule   `json:"-"`
	RulesV2 []RuleV2 `json:"-"`
	DNS     DNS      `json:"dns"`
}

// policyCommon is the part both versions share when marshalling.
type policyCommon struct {
	Version  int      `json:"version"`
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Mode     string   `json:"mode,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	Active   bool     `json:"active,omitempty"`
	Created  int64    `json:"created,omitempty"`
	Modified int64    `json:"modified,omitempty"`
	Zones    []Zone   `json:"zones,omitempty"`
	Defaults Defaults `json:"defaults"`
	DNS      DNS      `json:"dns,omitempty"`
}

// MarshalJSON emits version 1's string selectors or version 2's structured
// selectors under the same "rules" key.
func (p Policy) MarshalJSON() ([]byte, error) {
	c := policyCommon{
		Version: p.Version, ID: p.ID, Name: p.Name, Mode: p.Mode, Notes: p.Notes,
		Active: p.Active, Created: p.Created, Modified: p.Modified,
		Zones: p.Zones, Defaults: p.Defaults, DNS: p.DNS,
	}
	if p.Version == 2 {
		return json.Marshal(struct {
			policyCommon
			Rules []RuleV2 `json:"rules"`
		}{c, append([]RuleV2(nil), p.RulesV2...)})
	}
	return json.Marshal(struct {
		policyCommon
		Rules []Rule `json:"rules"`
	}{c, append([]Rule(nil), p.Rules...)})
}

// UnmarshalJSON reads either policy version strictly, so a misspelled field is
// an error rather than a rule that silently never matches.
func (p *Policy) UnmarshalJSON(b []byte) error {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return err
	}
	var raw struct {
		Version  int             `json:"version"`
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Mode     string          `json:"mode"`
		Notes    string          `json:"notes"`
		Active   bool            `json:"active"`
		Created  int64           `json:"created"`
		Modified int64           `json:"modified"`
		Zones    []Zone          `json:"zones"`
		Defaults Defaults        `json:"defaults"`
		Rules    json.RawMessage `json:"rules"`
		DNS      DNS             `json:"dns"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	p.Version = raw.Version
	p.ID, p.Name, p.Mode, p.Notes = raw.ID, raw.Name, raw.Mode, raw.Notes
	p.Active, p.Created, p.Modified = raw.Active, raw.Created, raw.Modified
	p.Zones, p.Defaults, p.DNS = raw.Zones, raw.Defaults, raw.DNS
	p.Rules, p.RulesV2 = nil, nil
	if len(raw.Rules) == 0 || string(raw.Rules) == "null" {
		return nil
	}
	if raw.Version == 2 {
		var rules []RuleV2
		rd := json.NewDecoder(bytes.NewReader(raw.Rules))
		rd.DisallowUnknownFields()
		if err := rd.Decode(&rules); err != nil {
			return err
		}
		p.RulesV2 = rules
		return nil
	}
	var rules []Rule
	rd := json.NewDecoder(bytes.NewReader(raw.Rules))
	rd.DisallowUnknownFields()
	if err := rd.Decode(&rules); err != nil {
		return err
	}
	p.Rules = rules
	return nil
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

// maxRules bounds a policy: every rule is tried against every observed
// connection.
const maxRules = 1000

// Parse reads and validates a policy. A misspelled field is an error: it
// would otherwise quietly mean "deny by default".
func Parse(r io.Reader) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate fills in the defaults and rejects anything that could never
// match, so a typo cannot pass for a rule that simply saw no traffic.
func (p *Policy) Validate() error {
	if p.Version != 0 && p.Version != 1 && p.Version != 2 {
		return fmt.Errorf("policy version %d is not supported", p.Version)
	}
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Version == 2 {
		if len(p.Rules) > 0 {
			return fmt.Errorf("version 2 policy has version 1 rules")
		}
		if p.Mode == "" {
			p.Mode = "precedence"
		}
		if p.Mode != "precedence" && p.Mode != "first-match" {
			return fmt.Errorf("policy mode %q is not precedence or first-match", p.Mode)
		}
	} else if len(p.RulesV2) > 0 {
		return fmt.Errorf("version 1 policy has version 2 rules")
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
	if p.Version == 2 && len(p.RulesV2) > maxRulesV2 {
		return fmt.Errorf("too many rules (%d, at most %d)", len(p.RulesV2), maxRulesV2)
	}
	if p.Version != 2 && len(p.Rules) > maxRules {
		return fmt.Errorf("too many rules (%d, at most %d)", len(p.Rules), maxRules)
	}
	zones := map[string]bool{}
	for _, z := range p.Zones {
		if z.Name == "" || zones[z.Name] {
			return fmt.Errorf("duplicate or empty zone name %q", z.Name)
		}
		zones[z.Name] = true
		for _, d := range z.Devices {
			if err := checkDevice(d); err != nil {
				return fmt.Errorf("zone %q: %w", z.Name, err)
			}
		}
	}
	if p.Version == 2 {
		if err := p.validateRulesV2(zones); err != nil {
			return err
		}
	} else {
		for _, r := range p.Rules {
			if r.From == "" || r.To == "" {
				return fmt.Errorf("rule %q needs from and to", r.Name)
			}
			if r.Action != "allow" && r.Action != "deny" {
				return fmt.Errorf("rule %q action %q is not allow or deny", r.Name, r.Action)
			}
			for _, sel := range []string{r.From, r.To} {
				if err := checkSelector(sel, zones); err != nil {
					return fmt.Errorf("rule %q: %w", r.Name, err)
				}
			}
			for _, port := range r.Ports {
				if _, _, err := parsePort(port); err != nil {
					return fmt.Errorf("rule %q: %w", r.Name, err)
				}
			}
		}
	}
	for _, names := range [][]string{p.DNS.Block, p.DNS.Allow} {
		for _, n := range names {
			if err := checkGlob(n); err != nil {
				return fmt.Errorf("dns: %w", err)
			}
		}
	}
	return nil
}

func checkGlob(pat string) error {
	if _, err := path.Match(pat, ""); err != nil {
		return fmt.Errorf("bad pattern %q: %w", pat, err)
	}
	return nil
}

func checkDevice(pat string) error {
	if strings.HasPrefix(pat, "ssid:") {
		return fmt.Errorf("device selector %q: a connection does not record its SSID", pat)
	}
	for _, prefix := range []string{"label:", "role:", "device:"} {
		if strings.HasPrefix(pat, prefix) {
			return checkGlob(pat[len(prefix):])
		}
	}
	return checkGlob(pat)
}

func checkSelector(sel string, zones map[string]bool) error {
	sel = strings.TrimSpace(sel)
	kind, val, ok := strings.Cut(sel, ":")
	if !ok {
		return checkGlob(sel)
	}
	switch kind {
	case "zone":
		if val != "any" && !zones[val] {
			return fmt.Errorf("selector %q: no such zone", sel)
		}
	case "site", "domain":
		return checkGlob(val)
	case "ip":
		if strings.Contains(val, "/") {
			if _, err := netip.ParsePrefix(val); err != nil {
				return fmt.Errorf("selector %q: %w", sel, err)
			}
		} else if _, err := netip.ParseAddr(val); err != nil {
			return fmt.Errorf("selector %q: %w", sel, err)
		}
	case "asn":
		if _, err := strconv.ParseUint(strings.TrimPrefix(val, "AS"), 10, 32); err != nil {
			return fmt.Errorf("selector %q: %w", sel, err)
		}
	case "country":
		if val == "" {
			return fmt.Errorf("selector %q: empty country", sel)
		}
	default:
		// An unprefixed glob over an IPv6 address has colons in it too.
		if _, err := netip.ParseAddr(sel); err != nil {
			return fmt.Errorf("selector %q: unknown kind %q", sel, kind)
		}
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
	default:
		return glob(pat, label) || glob(pat, id)
	}
}

// Conn is an observed connection, from the point of view of the device here.
type Conn struct {
	Zone      string `json:"zone,omitempty"`      // the device's zone
	PeerZone  string `json:"peer_zone,omitempty"` // the remote end's zone, when it is a device here too
	Device    string `json:"device,omitempty"`    // the device here, for device/label/role selectors
	Label     string `json:"label,omitempty"`
	Role      string `json:"role,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Process   string `json:"process,omitempty"` // app/process identity when known
	Via       string `json:"via,omitempty"`     // the process that launched it, when known
	Direction string `json:"direction"`         // out, in, local
	Name      string `json:"name,omitempty"`    // the remote end's best name
	Host      string `json:"host,omitempty"`    // a host name, when distinct from Name
	QName     string `json:"qname,omitempty"`   // a DNS question name
	Class     string `json:"class,omitempty"`   // broadcast, multicast, local, bonjour
	IP        string `json:"ip,omitempty"`      // the remote end's address
	Port      string `json:"port,omitempty"`    // the port served
	Proto     string `json:"proto,omitempty"`
	ASN       uint32 `json:"asn,omitempty"`
	Country   string `json:"country,omitempty"`
	Profile   string `json:"profile,omitempty"` // the active profile, when profiles exist
	Now       int64  `json:"now,omitempty"`     // unix ms, for temporary rule expiry
}

// endpoint is one end of a connection as a rule sees it. Only the remote end
// has a name and an address: the device here is selected through its zone.
type endpoint struct {
	zone, name, ip string
	asn            uint32
	country        string
}

// Decide returns the first matching rule and whether it allows the
// connection. A rule's from and to follow who opened it: an inbound
// connection is from the remote end to the device's zone, so "from zone:iot"
// does not cover traffic someone else sent to the zone.
func (p *Policy) Decide(c Conn) (rule string, allow bool, matched bool) {
	if p.Version == 2 {
		d := p.Evaluate(c)
		return d.Rule, d.Action != ActionDeny, d.Matched
	}
	return p.decideV1(c)
}

// decideV1 is the original first-match evaluator. It stays frozen so a saved
// version 1 policy keeps behaving exactly as it did.
func (p *Policy) decideV1(c Conn) (rule string, allow bool, matched bool) {
	if c.Direction == "external" {
		return "", false, false
	}
	here := endpoint{zone: c.Zone}
	there := endpoint{zone: c.PeerZone, name: c.Name, ip: c.IP, asn: c.ASN, country: c.Country}
	src, dst := here, there
	if c.Direction == "in" {
		src, dst = there, here
	}
	for _, r := range p.Rules {
		if src.matches(r.From) && dst.matches(r.To) && portsMatch(r.Ports, c.Port, c.Proto) {
			return r.Name, r.Action == "allow", true
		}
	}
	switch c.Direction {
	case "out":
		return "", p.Defaults.Egress == "allow", false
	case "in":
		return "", p.Defaults.Ingress == "allow", false
	case "local":
		// Between two zones is leaving the zone, whichever network carries it.
		if c.PeerZone == c.Zone {
			return "", p.Defaults.IntraZone == "allow", false
		}
		return "", p.Defaults.Egress == "allow", false
	}
	return "", true, false
}

func (e endpoint) matches(sel string) bool {
	sel = strings.TrimSpace(sel)
	switch {
	case sel == "any" || sel == "*":
		return true
	case sel == "zone:any":
		return e.zone != ""
	case strings.HasPrefix(sel, "zone:"):
		return e.zone != "" && e.zone == sel[len("zone:"):]
	case e.name == "" && e.ip == "":
		return false // the device here is only selected by its zone
	case strings.HasPrefix(sel, "site:"):
		site := graph.Site(e.name)
		return site != "" && glob(sel[len("site:"):], site)
	case strings.HasPrefix(sel, "domain:"):
		return glob(sel[len("domain:"):], e.name)
	case strings.HasPrefix(sel, "ip:"):
		pat := sel[len("ip:"):]
		if strings.Contains(pat, "/") {
			p, err := netip.ParsePrefix(pat)
			a, aerr := netip.ParseAddr(e.ip)
			return err == nil && aerr == nil && p.Contains(a)
		}
		return e.ip == pat
	case strings.HasPrefix(sel, "asn:"):
		n, err := strconv.ParseUint(strings.TrimPrefix(sel[len("asn:"):], "AS"), 10, 32)
		return err == nil && uint32(n) == e.asn
	case strings.HasPrefix(sel, "country:"):
		return strings.EqualFold(sel[len("country:"):], e.country)
	}
	return glob(sel, e.name) || glob(sel, e.ip)
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
	port, proto, _ := strings.Cut(s, "/")
	port, proto = strings.TrimSpace(port), strings.ToLower(strings.TrimSpace(proto))
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", "", fmt.Errorf("port %q: want NUMBER or NUMBER/PROTO", s)
	}
	return port, proto, nil
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
