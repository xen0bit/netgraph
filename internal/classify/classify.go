// Package classify says what kind of thing a device probably is, from what it
// was seen saying about itself. It is a pure function over strings that came off
// the network, so a device can claim to be anything: every verdict carries the
// signals behind it, and a person can overrule it.
package classify

import (
	"cmp"
	"slices"
	"strings"
)

// Device types. These names are also the map's icon names (web/src/js/map/icons.js).
const (
	Unknown  = ""
	Router   = "router"
	AP       = "ap"
	Switch   = "switch"
	Phone    = "phone"
	Tablet   = "tablet"
	Computer = "laptop"
	TV       = "tv"
	Speaker  = "speaker"
	Printer  = "printer"
	Camera   = "camera"
	NAS      = "nas"
	Server   = "server"
	Game     = "game"
	IoT      = "iot"
)

// Types is every type a verdict or a person can name.
var Types = []string{Router, AP, Switch, Phone, Tablet, Computer, TV, Speaker, Printer, Camera, NAS, Server, Game, IoT}

// Confidence levels.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Input is what was observed about a device. Every field is attacker-controlled.
type Input struct {
	Vendor       string
	Role         string   // the store's own: router, access_point, switch
	Hostnames    []string // DHCP, mDNS, NetBIOS, LLMNR, reverse DNS
	Services     []string // mDNS instance keys: "office printer._ipp._tcp.local"
	Models       []string // mDNS TXT model strings: "Brother HL-L2350DW"
	Fingerprints []string // DHCP vendor classes and JA4s
	UserAgents   []string
	UPnP         []string // SSDP server strings
	Serves       []string // ports clients connected to: "631/tcp"
}

// Reason is one signal behind a verdict.
type Reason struct {
	Signal string `json:"signal"` // vendor, hostname, service, model, fingerprint, user_agent, upnp, port, role
	Value  string `json:"value"`  // what was seen, as seen
	Says   string `json:"says"`   // the type it points to
	Weight int    `json:"weight"`
}

// Verdict is the answer, with its reasons, strongest first. Type is empty when
// nothing pointed anywhere.
type Verdict struct {
	Type       string   `json:"type,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Reasons    []Reason `json:"reasons,omitempty"`
}

// Each input is bounded: a device can announce as much as it likes.
const (
	maxValues = 64
	maxLen    = 256
	maxReason = 12
)

func clean(in []string) []string {
	if len(in) > maxValues {
		in = in[:maxValues]
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if len(s) > maxLen {
			s = s[:maxLen]
		}
		out = append(out, s)
	}
	return out
}

// Classify weighs every signal and names the type with the most behind it. It
// sums at most the strongest signal per kind for each type, so one long hostname
// list can't outvote the other evidence by repeating itself.
func Classify(in Input) Verdict {
	type kindType struct{ signal, typ string }
	best := map[kindType]Reason{}
	add := func(signal, value string, table []rule) {
		low := strings.ToLower(value)
		for _, r := range table {
			if !r.match(low) {
				continue
			}
			k := kindType{signal, r.typ}
			if have, ok := best[k]; !ok || r.weight > have.Weight {
				best[k] = Reason{Signal: signal, Value: value, Says: r.typ, Weight: r.weight}
			}
		}
	}
	each := func(signal string, values []string, table []rule) {
		for _, v := range clean(values) {
			add(signal, v, table)
		}
	}
	switch in.Role {
	case "router":
		best[kindType{"role", Router}] = Reason{Signal: "role", Value: "routes for this network", Says: Router, Weight: 20}
	case "access_point":
		best[kindType{"role", AP}] = Reason{Signal: "role", Value: "broadcasts a Wi-Fi network", Says: AP, Weight: 20}
	}
	if in.Role != "" && in.Role != "router" && in.Role != "access_point" && strings.Contains(strings.ToLower(in.Role), "switch") {
		best[kindType{"role", Switch}] = Reason{Signal: "role", Value: "speaks LLDP, as switches do", Says: Switch, Weight: 12}
	}
	each("vendor", clean([]string{in.Vendor}), vendorRules)
	each("hostname", in.Hostnames, hostRules)
	each("service", in.Services, serviceRules)
	each("model", in.Models, modelRules)
	each("fingerprint", in.Fingerprints, fingerprintRules)
	each("user_agent", in.UserAgents, agentRules)
	each("upnp", in.UPnP, upnpRules)
	each("port", in.Serves, portRules)

	totals := map[string]int{}
	var reasons []Reason
	for _, r := range best {
		totals[r.Says] += r.Weight
		reasons = append(reasons, r)
	}
	if len(reasons) == 0 {
		return Verdict{}
	}
	var top, second int
	var typ string
	// Types in their fixed order: a tie must not depend on a map's.
	for _, t := range Types {
		switch v := totals[t]; {
		case v > top:
			second, top, typ = top, v, t
		case v > second:
			second = v
		}
	}
	slices.SortFunc(reasons, func(a, b Reason) int {
		return cmp.Or(cmp.Compare(b.Weight, a.Weight), cmp.Compare(a.Signal, b.Signal), cmp.Compare(a.Says, b.Says), cmp.Compare(a.Value, b.Value))
	})
	if len(reasons) > maxReason {
		reasons = reasons[:maxReason]
	}
	v := Verdict{Type: typ, Reasons: reasons}
	lead := top - second
	switch {
	case top >= 8 && lead >= 5:
		v.Confidence = High
	case top >= 4 && lead >= 2:
		v.Confidence = Medium
	default:
		v.Confidence = Low
	}
	return v
}

// Valid reports whether a person may name this type.
func Valid(t string) bool { return slices.Contains(Types, t) }
