package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Decision is the result of evaluating one connection. Action is allow, deny
// or ask. Ask is not a denial: a passive server records it as "would ask".
type Decision struct {
	Action   string `json:"action"`
	Matched  bool   `json:"matched"`
	Rule     string `json:"rule,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	Priority string `json:"priority,omitempty"` // the matched rule's
	Reason   string `json:"reason"`
	WouldAsk bool   `json:"would_ask,omitempty"`
}

// Match is one rule that matched a connection, for explain.
type Match struct {
	Rule   string `json:"rule"`
	RuleID string `json:"rule_id,omitempty"`
	Action string `json:"action"`
	Rank   string `json:"rank"`
	Reason string `json:"reason,omitempty"`
}

// Explanation says why a connection got its decision, and every other rule
// that also matched. The first Match is the winner.
type Explanation struct {
	Conn     Conn     `json:"conn"`
	Decision Decision `json:"decision"`
	Matches  []Match  `json:"matches,omitempty"`
}

// Evaluate returns a structured decision for either policy version.
func (p *Policy) Evaluate(c Conn) Decision {
	if p.Version == 2 {
		return p.evaluateV2(c)
	}
	rule, allow, matched := p.decideV1(c)
	if matched {
		if allow {
			return Decision{Action: ActionAllow, Matched: true, Rule: rule, Reason: "allowed by rule " + rule}
		}
		return Decision{Action: ActionDeny, Matched: true, Rule: rule, Reason: "denied by rule " + rule}
	}
	if c.Direction == "external" {
		return Decision{Action: ActionDeny, Reason: "outside the observed network"}
	}
	action := ActionDeny
	if allow {
		action = ActionAllow
	}
	return Decision{Action: action, Reason: "default " + c.Direction + " " + action}
}

// Explain returns the winning decision and all matching rules, winner first.
func (p *Policy) Explain(c Conn) Explanation {
	if p.Version != 2 {
		return Explanation{Conn: c, Decision: p.Evaluate(c)}
	}
	var best *RuleV2
	var bestRank ruleRank
	var matches []rankedRule
	for i := range p.RulesV2 {
		r := &p.RulesV2[i]
		if !p.matchRule(c, r) {
			continue
		}
		rank := rankFor(c, *r, i)
		matches = append(matches, rankedRule{rule: r, rank: rank, index: i})
		if best == nil || better(rank, bestRank) {
			best, bestRank = r, rank
		}
	}
	d := p.defaultDecision(c)
	if best != nil {
		d = matched(best)
	}
	slices.SortStableFunc(matches, func(a, b rankedRule) int {
		if better(a.rank, b.rank) {
			return -1
		}
		if better(b.rank, a.rank) {
			return 1
		}
		return a.index - b.index
	})
	out := Explanation{Conn: c, Decision: d}
	for _, m := range matches {
		out.Matches = append(out.Matches, Match{
			Rule: m.rule.Name, RuleID: m.rule.ID, Action: m.rule.Action,
			Rank: m.rank.String(), Reason: m.rank.Why(),
		})
	}
	return out
}

func (p *Policy) evaluateV2(c Conn) Decision {
	var best *RuleV2
	var bestRank ruleRank
	for i := range p.RulesV2 {
		r := &p.RulesV2[i]
		if !p.matchRule(c, r) {
			continue
		}
		rank := rankFor(c, *r, i)
		if best == nil || better(rank, bestRank) {
			best, bestRank = r, rank
		}
	}
	if best == nil {
		return p.defaultDecision(c)
	}
	return matched(best)
}

func matched(r *RuleV2) Decision {
	return Decision{
		Action: r.Action, Matched: true, Rule: r.Name, RuleID: r.ID, Priority: r.Priority,
		Reason: "matched " + r.Name, WouldAsk: r.Action == ActionAsk,
	}
}

func (p *Policy) defaultDecision(c Conn) Decision {
	if c.Direction == "external" {
		return Decision{Action: ActionDeny, Reason: "outside the observed network"}
	}
	var action string
	switch c.Direction {
	case "out":
		action = p.Defaults.Egress
	case "in":
		action = p.Defaults.Ingress
	case "local":
		if c.PeerZone == c.Zone {
			action = p.Defaults.IntraZone
		} else {
			action = p.Defaults.Egress
		}
	default:
		return Decision{Action: ActionAllow, Reason: "no direction"}
	}
	if action == "" {
		action = ActionDeny
	}
	return Decision{Action: action, Reason: "default " + c.Direction + " " + action}
}

func (p *Policy) matchRule(c Conn, r *RuleV2) bool {
	if !r.EnabledValue() {
		return false
	}
	if r.Profile != "" && r.Profile != c.Profile {
		return false
	}
	if r.Expiry > 0 {
		now := c.Now
		if now == 0 {
			now = time.Now().UnixMilli()
		}
		if now > r.Expiry {
			return false
		}
	}
	if r.Direction != "" && r.Direction != "both" && r.Direction != c.Direction {
		return false
	}
	if !matchLocal(r.Local, c) {
		return false
	}
	if !matchRemote(r.Remote, c) {
		return false
	}
	if r.Via.Type != "" && r.Via.Type != "any" && !globValue(r.Via, c.Via) {
		return false
	}
	if !matchPorts(r.Ports, c.Port, c.Proto) {
		return false
	}
	if r.Protocol != "" && r.Protocol != "any" {
		if !protoEqual(r.Protocol, c.Proto) {
			return false
		}
	}
	return true
}

func matchLocal(s Selector, c Conn) bool {
	switch s.Type {
	case "", "any":
		return true
	case "zone":
		for _, v := range s.Values {
			if v == "any" && c.Zone != "" || v == c.Zone {
				return true
			}
		}
	case "device":
		return anyGlob(s.Values, c.Device)
	case "label":
		return anyGlob(s.Values, c.Label)
	case "role":
		for _, v := range s.Values {
			if strings.EqualFold(v, c.Role) {
				return true
			}
		}
	case "app", "process":
		return anyGlob(s.Values, c.Process)
	case "owner":
		return anyGlob(s.Values, c.Owner)
	}
	return false
}

func matchRemote(s Selector, c Conn) bool {
	switch s.Type {
	case "", "any":
		return true
	case "ip":
		a, err := netip.ParseAddr(c.IP)
		if err != nil {
			return false
		}
		a = a.Unmap()
		for _, v := range s.Values {
			if strings.Contains(v, "/") {
				if p, err := netip.ParsePrefix(v); err == nil && p.Contains(a) {
					return true
				}
			} else if x, err := netip.ParseAddr(v); err == nil && x.Unmap() == a {
				return true
			}
		}
	case "host":
		return anyGlob(s.Values, c.Host) || anyGlob(s.Values, c.Name)
	case "domain":
		return anyDomain(s.Values, firstNonEmpty(c.Host, c.Name))
	case "dns":
		return anyDomain(s.Values, c.QName)
	case "broadcast", "multicast", "bonjour", "local":
		class := c.Class
		if class == "" {
			class = inferredClass(c.IP)
		}
		for _, v := range s.Values {
			if strings.EqualFold(v, class) {
				return true
			}
		}
	}
	return false
}

func anyGlob(values []string, s string) bool {
	for _, v := range values {
		if globName(v, s) {
			return true
		}
	}
	return false
}

func anyDomain(values []string, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return false
	}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "*" || v == "any" {
			return true
		}
		v = strings.TrimPrefix(v, "*.")
		v = strings.TrimPrefix(v, ".")
		if name == v || strings.HasSuffix(name, "."+v) {
			return true
		}
		if globName(v, name) {
			return true
		}
	}
	return false
}

func globValue(s Selector, value string) bool {
	if s.Type == "" || s.Type == "any" {
		return true
	}
	return anyGlob(s.Values, value)
}

func matchPorts(specs []string, port, proto string) bool {
	if len(specs) == 0 {
		return true
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, spec := range specs {
		p, err := parsePortSpec(spec)
		if err != nil {
			continue
		}
		if n < p.lo || n > p.hi {
			continue
		}
		if p.proto == "" || protoEqual(p.proto, proto) {
			return true
		}
	}
	return false
}

func protoEqual(a, b string) bool {
	an, aok := protocolNumber(a)
	bn, bok := protocolNumber(b)
	if aok && bok {
		return an == bn
	}
	return strings.EqualFold(a, b)
}

func inferredClass(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	switch {
	case a.IsMulticast():
		return "multicast"
	case a.Is4() && a == netip.MustParseAddr("255.255.255.255"):
		return "broadcast"
	case a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLoopback():
		return "local"
	}
	return ""
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// rankedRule carries a rule and the rank it earned against one connection.
type rankedRule struct {
	rule  *RuleV2
	rank  ruleRank
	index int
}

type ruleRank struct {
	priority   int
	remoteType int
	values     int // fewer values is more specific
	specific   int
	ports      int // fewer ports is more specific
	portStart  int
	protocol   int
	process    int
	via        int
	owner      int
	direction  int
	action     int
	order      int
}

func (r ruleRank) String() string {
	return fmt.Sprintf("priority=%d remote=%d values=%d specific=%d ports=%d port_start=%d protocol=%d process=%d via=%d owner=%d direction=%d action=%d order=%d",
		r.priority, r.remoteType, r.values, r.specific, r.ports, r.portStart, r.protocol, r.process, r.via, r.owner, r.direction, r.action, r.order)
}

func (r ruleRank) Why() string {
	var b strings.Builder
	fmt.Fprintf(&b, "priority %d, remote type %d", r.priority, r.remoteType)
	if r.values < 1<<20 {
		fmt.Fprintf(&b, ", %d value(s)", r.values)
	}
	if r.specific > 0 {
		fmt.Fprintf(&b, ", specificity %d", r.specific)
	}
	if r.ports < 1<<20 {
		fmt.Fprintf(&b, ", ports %d-%d", r.portStart, r.portStart+r.ports-1)
	}
	return b.String()
}

func better(a, b ruleRank) bool {
	switch {
	case a.priority != b.priority:
		return a.priority > b.priority
	case a.remoteType != b.remoteType:
		return a.remoteType > b.remoteType
	case a.values != b.values:
		return a.values < b.values
	case a.specific != b.specific:
		return a.specific > b.specific
	case a.ports != b.ports:
		return a.ports < b.ports
	case a.portStart != b.portStart:
		return a.portStart < b.portStart
	case a.protocol != b.protocol:
		return a.protocol > b.protocol
	case a.process != b.process:
		return a.process > b.process
	case a.via != b.via:
		return a.via > b.via
	case a.owner != b.owner:
		return a.owner > b.owner
	case a.direction != b.direction:
		return a.direction > b.direction
	case a.action != b.action:
		return a.action > b.action
	default:
		return a.order < b.order
	}
}

func rankFor(c Conn, r RuleV2, index int) ruleRank {
	rank := ruleRank{order: index}
	switch r.Priority {
	case PriorityExtraHigh:
		rank.priority = 3
	case PriorityHigh:
		rank.priority = 2
	default:
		rank.priority = 1
	}
	rank.remoteType = remoteRank(r.Remote.Type)
	rank.values = len(r.Remote.Values)
	if r.Remote.Type == "" || r.Remote.Type == "any" {
		rank.values = 1 << 20
	}
	rank.specific = selectorSpecificity(r.Remote)
	rank.ports, rank.portStart = portSpecificity(r.Ports, c.Port, c.Proto)
	if r.Protocol != "" && r.Protocol != "any" {
		rank.protocol = 1
	}
	if r.Local.Type == "app" || r.Local.Type == "process" || r.Local.Type == "device" || r.Local.Type == "label" {
		rank.process = 1
	}
	if r.Via.Type != "" && r.Via.Type != "any" {
		rank.via = 1
	}
	if r.Local.Type == "owner" {
		rank.owner = 1
	}
	if r.Direction == "both" || r.Direction == "" {
		rank.direction = 1
	} else {
		rank.direction = 2
	}
	switch r.Action {
	case ActionDeny:
		rank.action = 3
	case ActionAllow:
		rank.action = 2
	case ActionAsk:
		rank.action = 1
	}
	return rank
}

func remoteRank(t string) int {
	switch t {
	case "ip":
		return 9
	case "host":
		return 8
	case "domain":
		return 7
	case "dns":
		return 6
	case "broadcast":
		return 5
	case "multicast":
		return 4
	case "bonjour":
		return 3
	case "local":
		return 2
	default:
		return 1
	}
}

func selectorSpecificity(s Selector) int {
	best := 0
	for _, v := range s.Values {
		n := 0
		switch s.Type {
		case "ip":
			if strings.Contains(v, "/") {
				if p, err := netip.ParsePrefix(v); err == nil {
					n = p.Bits()
				}
			} else if a, err := netip.ParseAddr(v); err == nil {
				if a.Is4() {
					n = 32
				} else {
					n = 128
				}
			}
		case "domain", "dns":
			n = len(strings.Split(strings.Trim(strings.TrimPrefix(v, "*."), "."), "."))*1000 + len(v)
		case "host":
			n = len(v)
		default:
			n = 1
		}
		if n > best {
			best = n
		}
	}
	return best
}

func portSpecificity(specs []string, port, proto string) (count, start int) {
	count, start = 1<<20, 0
	n, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	for _, spec := range specs {
		p, err := parsePortSpec(spec)
		if err != nil {
			continue
		}
		if n < p.lo || n > p.hi || (p.proto != "" && !protoEqual(p.proto, proto)) {
			continue
		}
		c := p.hi - p.lo + 1
		if c < count || (c == count && p.lo < start) {
			count, start = c, p.lo
		}
	}
	return
}
