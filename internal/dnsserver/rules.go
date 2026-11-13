package dnsserver

import (
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

// List is a blocklist's name and its enabled entries.
type List struct {
	Name    string
	Entries []blocklist.Entry
}

// Client is what's known of whoever asked: the device holding the address, and
// its groups. A zero Client is someone unknown, to whom only rules for
// everyone apply.
type Client struct {
	MAC    string
	Groups []string
}

// Rules is a snapshot of everything that decides whether a name is answered:
// the enabled blocklists and the rules a person wrote. It never changes once
// built; the server swaps in a new one.
type Rules struct {
	lists  []namedMatcher
	all    ruleSet
	device map[string]*ruleSet // by MAC
	group  map[string]*ruleSet
	// Count and Entries say how big it is, for the status page.
	Count, Entries int
}

type namedMatcher struct {
	name string
	m    *blocklist.Matcher
}

// ruleSet is one scope's rules: names blocked and names allowed, each
// covering its subdomains, and whether every name is allowed.
type ruleSet struct {
	block, allow map[string]int64 // name -> rule ID
	allowAll     int64
}

func (r *ruleSet) add(rule model.DNSRule) {
	if rule.Pattern == "*" {
		if rule.Action == model.DNSAllow {
			r.allowAll = rule.ID
		}
		return
	}
	if r.block == nil {
		r.block, r.allow = map[string]int64{}, map[string]int64{}
	}
	if rule.Action == model.DNSAllow {
		r.allow[rule.Pattern] = rule.ID
	} else {
		r.block[rule.Pattern] = rule.ID
	}
}

// match finds the rule in m for name or its nearest parent.
func match(m map[string]int64, name string) (int64, bool) {
	if len(m) == 0 {
		return 0, false
	}
	for {
		if id, ok := m[name]; ok {
			return id, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return 0, false
		}
		name = name[i+1:]
	}
}

// decide is this scope's say on name: allowed, blocked (by which rule), or
// nothing.
func (r *ruleSet) decide(name string) (verdict, string) {
	if r == nil {
		return none, ""
	}
	if r.allowAll != 0 {
		return allowed, ""
	}
	if _, ok := match(r.allow, name); ok {
		return allowed, ""
	}
	if id, ok := match(r.block, name); ok {
		return blocked, "rule:" + strconv.FormatInt(id, 10)
	}
	return none, ""
}

type verdict int

const (
	none verdict = iota
	allowed
	blocked
)

// BuildRules makes a snapshot from the enabled lists and the rules. Rules
// arrive already checked by the store; one it can't use is skipped.
func BuildRules(lists []List, rules []model.DNSRule) *Rules {
	r := &Rules{all: ruleSet{}, device: map[string]*ruleSet{}, group: map[string]*ruleSet{}, Count: len(rules)}
	for _, l := range lists {
		if len(l.Entries) == 0 {
			continue
		}
		r.lists = append(r.lists, namedMatcher{name: l.Name, m: blocklist.New(l.Entries)})
		r.Entries += len(l.Entries)
	}
	for _, rule := range rules {
		rule.Pattern = strings.ToLower(rule.Pattern)
		switch rule.Scope {
		case model.DNSScopeAll:
			r.all.add(rule)
		case model.DNSScopeDevice:
			k := strings.ToLower(rule.ScopeValue)
			if r.device[k] == nil {
				r.device[k] = &ruleSet{}
			}
			r.device[k].add(rule)
		case model.DNSScopeGroup:
			if r.group[rule.ScopeValue] == nil {
				r.group[rule.ScopeValue] = &ruleSet{}
			}
			r.group[rule.ScopeValue].add(rule)
		}
	}
	return r
}

// Blocked says whether name is refused for c, and by what: "rule:<id>" or
// "list:<name>". The most specific say wins: the device's own rules, then
// its groups', then everyone's, then the blocklists (whose own exceptions,
// @@||name^, they apply themselves). Within a scope, allowing beats
// blocking.
func (r *Rules) Blocked(name string, c Client) (bool, string) {
	if r == nil {
		return false, ""
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return false, ""
	}
	if c.MAC != "" {
		if v, by := r.device[strings.ToLower(c.MAC)].decide(name); v != none {
			return v == blocked, by
		}
	}
	// Groups: an allow in any of them beats a block in another.
	var groupBlock string
	for _, g := range c.Groups {
		switch v, by := r.group[g].decide(name); v {
		case allowed:
			return false, ""
		case blocked:
			if groupBlock == "" {
				groupBlock = by
			}
		}
	}
	if groupBlock != "" {
		return true, groupBlock
	}
	if v, by := r.all.decide(name); v != none {
		return v == blocked, by
	}
	for _, l := range r.lists {
		if _, ok := l.m.MatchName(name); ok {
			return true, "list:" + l.name
		}
	}
	return false, ""
}
