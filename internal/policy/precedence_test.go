package policy

import (
	"strings"
	"testing"
)

func enabled() *bool { b := true; return &b }

func TestV2ParseAndValidate(t *testing.T) {
	doc := `{
	  "version": 2,
	  "name": "home",
	  "mode": "precedence",
	  "zones": [{"name":"iot","devices":["role:camera"]}],
	  "defaults": {"egress":"deny","ingress":"deny","intra_zone":"allow","dns":"allow"},
	  "rules": [
	    {"name":"https out","action":"allow","direction":"out","priority":"regular",
	     "local":{"type":"zone","values":["iot"]},
	     "remote":{"type":"domain","values":["*.vendor.example"]},
	     "ports":["443/tcp"],"protocol":"tcp"}
	  ]
	}`
	p, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 2 || len(p.RulesV2) != 1 {
		t.Fatalf("parsed %+v", p)
	}
	if p.RulesV2[0].Local.Type != "zone" || p.RulesV2[0].Remote.Type != "domain" {
		t.Fatalf("selectors: %+v", p.RulesV2[0])
	}
	d := p.Evaluate(Conn{Zone: "iot", Direction: "out", Name: "api.vendor.example", Port: "443", Proto: "tcp"})
	if d.Action != ActionAllow || !d.Matched {
		t.Fatalf("decision = %+v", d)
	}
}

func TestV2RejectsUnknowns(t *testing.T) {
	base := `{"version":2,"rules":[{"name":"x","action":"allow","local":{"type":"any"},"remote":{"type":"any"}}]}`
	for name, doc := range map[string]string{
		"unknown top field":   strings.Replace(base, `"version":2`, `"version":2,"nonsense":true`, 1),
		"unknown rule field":  strings.Replace(base, `"name":"x"`, `"name":"x","nonsense":true`, 1),
		"bad action":          strings.Replace(base, `"action":"allow"`, `"action":"maybe"`, 1),
		"bad local type":      strings.Replace(base, `{"type":"any"}`, `{"type":"ssid","values":["x"]}`, 1),
		"bad remote type":     strings.Replace(base, `{"type":"any"}`, `{"type":"asn","values":["1"]}`, 1),
		"bad ip":              strings.Replace(base, `{"type":"any"}`, `{"type":"ip","values":["10.0.0.0/99"]}`, 1),
		"bad port":            strings.Replace(base, `"action":"allow"`, `"action":"allow","ports":["70000"]`, 1),
		"temporary no expiry": strings.Replace(base, `"action":"allow"`, `"action":"allow","lifetime":"temporary"`, 1),
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestV2Precedence(t *testing.T) {
	rule := func(name, action string, f func(*RuleV2)) RuleV2 {
		r := RuleV2{Name: name, Action: action, Local: Selector{Type: "any"}, Remote: Selector{Type: "any"}, Enabled: enabled()}
		if f != nil {
			f(&r)
		}
		return r
	}
	conn := Conn{Zone: "iot", Direction: "out", Name: "api.vendor.example", IP: "203.0.113.7", Port: "443", Proto: "tcp", Process: "store", Via: "launchd", Owner: "alice"}
	tests := []struct {
		name  string
		rules []RuleV2
		want  string
	}{
		{
			name: "priority beats specificity and action",
			rules: []RuleV2{
				rule("specific-deny", ActionDeny, func(r *RuleV2) {
					r.Remote = Selector{Type: "domain", Values: []string{"api.vendor.example"}}
					r.Ports = []string{"443"}
				}),
				rule("extra-allow", ActionAllow, func(r *RuleV2) { r.Priority = PriorityExtraHigh }),
			},
			want: "extra-allow",
		},
		{
			name: "ip beats domain",
			rules: []RuleV2{
				rule("domain", ActionAllow, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
				rule("ip", ActionDeny, func(r *RuleV2) { r.Remote = Selector{Type: "ip", Values: []string{"203.0.113.7"}} }),
			},
			want: "ip",
		},
		{
			name: "fewer values wins",
			rules: []RuleV2{
				rule("two", ActionAllow, func(r *RuleV2) {
					r.Remote = Selector{Type: "domain", Values: []string{"vendor.example", "other.example"}}
				}),
				rule("one", ActionDeny, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
			},
			want: "one",
		},
		{
			name: "longer suffix wins",
			rules: []RuleV2{
				rule("short", ActionAllow, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
				rule("long", ActionDeny, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"api.vendor.example"}} }),
			},
			want: "long",
		},
		{
			name: "narrow port range wins",
			rules: []RuleV2{
				rule("wide", ActionAllow, func(r *RuleV2) { r.Ports = []string{"400-500"} }),
				rule("narrow", ActionDeny, func(r *RuleV2) { r.Ports = []string{"443"} }),
			},
			want: "narrow",
		},
		{
			name: "specific protocol wins",
			rules: []RuleV2{
				rule("any-proto", ActionAllow, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
				rule("tcp", ActionDeny, func(r *RuleV2) {
					r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}}
					r.Protocol = "tcp"
				}),
			},
			want: "tcp",
		},
		{
			name: "process selector wins",
			rules: []RuleV2{
				rule("zone", ActionAllow, func(r *RuleV2) { r.Local = Selector{Type: "zone", Values: []string{"iot"}} }),
				rule("process", ActionDeny, func(r *RuleV2) {
					r.Local = Selector{Type: "process", Values: []string{"store"}}
				}),
			},
			want: "process",
		},
		{
			name: "specific direction wins",
			rules: []RuleV2{
				rule("both", ActionAllow, func(r *RuleV2) {
					r.Direction = "both"
					r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}}
				}),
				rule("out", ActionDeny, func(r *RuleV2) {
					r.Direction = "out"
					r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}}
				}),
			},
			want: "out",
		},
		{
			name: "deny beats allow",
			rules: []RuleV2{
				rule("allow", ActionAllow, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
				rule("deny", ActionDeny, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
			},
			want: "deny",
		},
		{
			name: "ask loses to allow",
			rules: []RuleV2{
				rule("ask", ActionAsk, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
				rule("allow", ActionAllow, func(r *RuleV2) { r.Remote = Selector{Type: "domain", Values: []string{"vendor.example"}} }),
			},
			want: "allow",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Version: 2, Zones: []Zone{{Name: "iot", Devices: []string{"any"}}}, Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"}, RulesV2: tt.rules}
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			got := p.Evaluate(conn)
			if got.Rule != tt.want {
				t.Fatalf("rule = %q, want %q; %+v", got.Rule, tt.want, got)
			}
		})
	}
}

func TestV2ExplainAndAsk(t *testing.T) {
	p := &Policy{
		Version:  2,
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2: []RuleV2{{
			Name: "ask vendor", Action: ActionAsk,
			Local: Selector{Type: "any"}, Remote: Selector{Type: "domain", Values: []string{"vendor.example"}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	c := Conn{Direction: "out", Name: "api.vendor.example", Port: "443", Proto: "tcp"}
	d := p.Evaluate(c)
	if d.Action != ActionAsk || !d.WouldAsk {
		t.Fatalf("decision = %+v", d)
	}
	e := p.Explain(c)
	if len(e.Matches) != 1 || e.Matches[0].Rule != "ask vendor" || e.Decision.Action != ActionAsk {
		t.Fatalf("explanation = %+v", e)
	}
}
