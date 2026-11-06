package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// AuditFinding is one maintainability problem in a policy.
type AuditFinding struct {
	Rule     string `json:"rule"`
	RuleID   string `json:"rule_id,omitempty"`
	Kind     string `json:"kind"` // redundant, shadowed, contradictory, invalid, unnecessary-priority, blocklist-override, expired
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Other    string `json:"other,omitempty"`
}

// AuditReport is deterministic: the same policy and inputs give the same
// findings in the same order.
type AuditReport struct {
	PolicyHash string         `json:"policy_hash,omitempty"`
	Findings   []AuditFinding `json:"findings,omitempty"`
	Summary    map[string]int `json:"summary"`
	Gaps       []string       `json:"gaps,omitempty"`
}

// BlocklistMatcher is the small part of a blocklist index audit needs.
type BlocklistMatcher interface {
	MatchName(string) (string, bool)
	MatchIP(string) (string, bool)
}

// Audit checks a version 2 policy. It is conservative: a rule is only called
// redundant when every connection it can match is covered by a rule that
// outranks it.
func Audit(p *Policy, profiles []string, matcher BlocklistMatcher) *AuditReport {
	rep := &AuditReport{PolicyHash: p.Hash(), Summary: map[string]int{}}
	if p.Version != 2 {
		rep.Gaps = append(rep.Gaps, "audit is for version 2 policies; version 1 is evaluated first-match")
		return rep
	}
	known := map[string]bool{}
	for _, name := range profiles {
		known[name] = true
	}
	now := time.Now().UnixMilli()
	for i := range p.RulesV2 {
		r := &p.RulesV2[i]
		if !r.EnabledValue() {
			continue
		}
		add := func(kind, severity, detail string, other string) {
			rep.Findings = append(rep.Findings, AuditFinding{
				Rule: r.Name, RuleID: r.ID, Kind: kind, Severity: severity, Detail: detail, Other: other,
			})
			rep.Summary[kind]++
		}
		if r.Expiry > 0 && r.Expiry < now {
			add("expired", "info", "the rule has expired and no longer matches", "")
		}
		if r.Profile != "" && len(known) > 0 && !known[r.Profile] {
			add("invalid", "medium", fmt.Sprintf("profile %q does not exist", r.Profile), "")
		}
		if r.Local.Type == "zone" {
			for _, z := range r.Local.Values {
				found := false
				for _, zone := range p.Zones {
					if zone.Name == z {
						found = true
						break
					}
				}
				if !found {
					add("invalid", "medium", fmt.Sprintf("zone %q does not exist", z), "")
				}
			}
		}
		if r.Action == ActionAllow && matcher != nil {
			for _, v := range r.Remote.Values {
				if r.Remote.Type == "ip" {
					if e, ok := matcher.MatchIP(v); ok {
						add("blocklist-override", "high", fmt.Sprintf("the allow rule covers blocklisted address %s", e), "")
					}
				} else if r.Remote.Type == "domain" || r.Remote.Type == "host" || r.Remote.Type == "dns" {
					if e, ok := matcher.MatchName(strings.TrimPrefix(v, "*.")); ok {
						add("blocklist-override", "high", fmt.Sprintf("the allow rule covers blocklisted name %s", e), "")
					}
				}
			}
		}
		for j := range p.RulesV2 {
			if i == j {
				continue
			}
			o := &p.RulesV2[j]
			if !o.EnabledValue() {
				continue
			}
			if !overlaps(*r, *o) {
				continue
			}
			if r.Action != o.Action && (r.Remote.Type == o.Remote.Type || r.Remote.Type == "any" || o.Remote.Type == "any") {
				if sameRemoteValues(r.Remote, o.Remote) {
					add("contradictory", "high", fmt.Sprintf("%s and %s match the same names with different actions", r.Name, o.Name), o.Name)
				}
			}
			if covers(*o, *r) && outranks(*o, *r) {
				kind := "shadowed"
				detail := fmt.Sprintf("%s is covered by %s", r.Name, o.Name)
				if o.Action == r.Action {
					kind = "redundant"
					detail = fmt.Sprintf("%s has the same effect as %s", r.Name, o.Name)
				}
				add(kind, "medium", detail, o.Name)
			}
		}
	}
	sort.SliceStable(rep.Findings, func(a, b int) bool {
		if rep.Findings[a].Rule != rep.Findings[b].Rule {
			return rep.Findings[a].Rule < rep.Findings[b].Rule
		}
		if rep.Findings[a].Kind != rep.Findings[b].Kind {
			return rep.Findings[a].Kind < rep.Findings[b].Kind
		}
		return rep.Findings[a].Other < rep.Findings[b].Other
	})
	rep.Gaps = append(rep.Gaps,
		"unused rules need actual decision/agent usage; a simulation does not count as use",
		"blocklist overrides are checked only for literal names and addresses",
	)
	return rep
}

func overlaps(a, b RuleV2) bool {
	if a.Direction != "both" && b.Direction != "both" && a.Direction != b.Direction {
		return false
	}
	if !selectorsOverlap(a.Local, b.Local) || !selectorsOverlap(a.Remote, b.Remote) {
		return false
	}
	return portsOverlap(a.Ports, b.Ports) && protocolsOverlap(a.Protocol, b.Protocol)
}

func selectorsOverlap(a, b Selector) bool {
	if a.Type == "any" || b.Type == "any" {
		return true
	}
	if a.Type != b.Type {
		return false
	}
	for _, x := range a.Values {
		for _, y := range b.Values {
			if x == y || globName(x, y) || globName(y, x) {
				return true
			}
		}
	}
	return false
}

func sameRemoteValues(a, b Selector) bool {
	if a.Type != b.Type || len(a.Values) != len(b.Values) {
		return false
	}
	x := append([]string(nil), a.Values...)
	y := append([]string(nil), b.Values...)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func outranks(a, b RuleV2) bool {
	c := Conn{Direction: "out", Port: "0", Proto: "tcp"}
	return better(rankFor(c, a, 0), rankFor(c, b, 1))
}

func protocolsOverlap(a, b string) bool {
	return a == "" || b == "" || a == "any" || b == "any" || a == b
}

func portsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		px, err := parsePortSpec(x)
		if err != nil {
			continue
		}
		for _, y := range b {
			py, err := parsePortSpec(y)
			if err != nil {
				continue
			}
			if px.lo <= py.hi && py.lo <= px.hi && (px.proto == "" || py.proto == "" || px.proto == py.proto) {
				return true
			}
		}
	}
	return false
}

// covers says every connection b can match is also matched by a.
func covers(a, b RuleV2) bool {
	if a.Direction != "both" && a.Direction != b.Direction {
		return false
	}
	if !selectorCovers(a.Local, b.Local) || !selectorCovers(a.Remote, b.Remote) {
		return false
	}
	if !portsCover(a.Ports, b.Ports) || !protocolCovers(a.Protocol, b.Protocol) {
		return false
	}
	// A higher priority is not required for coverage, but a lower one does not
	// make b redundant: the evaluator may pick b first on a tie.
	return true
}

func selectorCovers(a, b Selector) bool {
	if a.Type == "any" {
		return true
	}
	if a.Type != b.Type {
		return false
	}
	for _, y := range b.Values {
		ok := false
		for _, x := range a.Values {
			if valueCovers(a.Type, x, y) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func valueCovers(kind, a, b string) bool {
	switch kind {
	case "ip":
		pa, errA := parsePrefixOrAddr(a)
		pb, errB := parsePrefixOrAddr(b)
		return errA == nil && errB == nil && pa.Contains(pb.Addr()) && pa.Bits() <= pb.Bits()
	case "domain", "dns":
		a = strings.TrimPrefix(strings.ToLower(a), "*.")
		b = strings.TrimPrefix(strings.ToLower(b), "*.")
		return b == a || strings.HasSuffix(b, "."+a)
	default:
		return a == b || globName(a, b)
	}
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 128
	if a.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(a.Unmap(), bits), nil
}

func portsCover(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, y := range b {
		py, err := parsePortSpec(y)
		if err != nil {
			return false
		}
		ok := false
		for _, x := range a {
			px, err := parsePortSpec(x)
			if err != nil {
				continue
			}
			if px.lo <= py.lo && px.hi >= py.hi && (px.proto == "" || px.proto == py.proto) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func protocolCovers(a, b string) bool {
	return a == "" || a == "any" || a == b
}
