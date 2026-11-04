package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestPolicyDecide(t *testing.T) {
	p := &Policy{
		Version:  1,
		Zones:    []Zone{{Name: "iot", Devices: []string{"label:plug-*"}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		Rules: []Rule{
			{Name: "https", From: "zone:iot", To: "site:*.vendor.example", Ports: []string{"443/tcp"}, Action: "allow"},
			{Name: "block", From: "any", To: "domain:ads.example", Action: "deny"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if z := p.ZoneFor("device:aa", "plug-1", ""); z != "iot" {
		t.Fatalf("zone = %q", z)
	}
	if rule, ok, matched := p.Decide(Conn{Zone: "iot", Direction: "out", Name: "api.vendor.example", IP: "1.2.3.4", Port: "443", Proto: "tcp"}); !ok || !matched || rule != "https" {
		t.Fatalf("https decision = %q %v %v", rule, ok, matched)
	}
	if _, ok, _ := p.Decide(Conn{Zone: "iot", Direction: "out", Name: "api.vendor.example", IP: "1.2.3.4", Port: "80", Proto: "tcp"}); ok {
		t.Fatal("port 80 was allowed")
	}
	if _, ok, _ := p.Decide(Conn{Zone: "unknown", Direction: "out", Name: "x", IP: "1.2.3.4", Port: "443", Proto: "tcp"}); ok {
		t.Fatal("unknown zone was allowed")
	}
}

func TestPolicyParseAndDNS(t *testing.T) {
	p, err := Parse(bytes.NewBufferString(`{"version":1,"defaults":{"egress":"deny","ingress":"deny","intra_zone":"allow","dns":"allow"},"zones":[{"name":"all","devices":["any"]}],"rules":[],"dns":{"block":["*.ads.example"],"allow":["ok.ads.example"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.DNSBlocked("x.ads.example") || p.DNSBlocked("ok.ads.example") || p.DNSBlocked("example.com") {
		t.Fatal("DNS block/allow did not match")
	}
}

// A rule follows who opened the connection: "from a zone" must not also cover
// traffic someone else sent to the zone.
func TestPolicyDirection(t *testing.T) {
	p := &Policy{
		Zones:    []Zone{{Name: "lan", Devices: []string{"any"}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "deny"},
		Rules: []Rule{
			{Name: "web-out", From: "zone:lan", To: "any", Ports: []string{"443/tcp"}, Action: "allow"},
			{Name: "ssh-in", From: "ip:10.9.0.0/16", To: "zone:lan", Ports: []string{"22"}, Action: "allow"},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	in := Conn{Zone: "lan", Direction: "in", IP: "203.0.113.9", Port: "443", Proto: "tcp"}
	if rule, ok, _ := p.Decide(in); ok || rule != "" {
		t.Errorf("an outbound rule allowed an inbound connection: %q", rule)
	}
	admin := Conn{Zone: "lan", Direction: "in", IP: "10.9.1.1", Port: "22", Proto: "tcp"}
	if rule, ok, _ := p.Decide(admin); !ok || rule != "ssh-in" {
		t.Errorf("inbound rule: %q %v", rule, ok)
	}
	out := Conn{Zone: "lan", Direction: "out", IP: "10.9.1.1", Port: "22", Proto: "tcp"}
	if rule, ok, _ := p.Decide(out); ok {
		t.Errorf("an inbound rule allowed an outbound connection: %q", rule)
	}
}

func TestPolicyLocalZones(t *testing.T) {
	p := &Policy{
		Zones:    []Zone{{Name: "iot", Devices: []string{"role:camera"}}, {Name: "lan", Devices: []string{"any"}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow"},
		Rules:    []Rule{{Name: "nvr", From: "zone:lan", To: "zone:iot", Ports: []string{"554"}, Action: "allow"}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		conn Conn
		want bool
	}{
		{"same zone", Conn{Zone: "iot", PeerZone: "iot", Direction: "local", IP: "10.0.0.2", Port: "80"}, true},
		{"other zone, default", Conn{Zone: "iot", PeerZone: "lan", Direction: "local", IP: "10.0.0.2", Port: "80"}, false},
		{"other zone, rule", Conn{Zone: "lan", PeerZone: "iot", Direction: "local", IP: "10.0.0.2", Port: "554"}, true},
		{"peer in no zone", Conn{Zone: "lan", Direction: "local", IP: "10.0.0.2", Port: "80"}, false},
	} {
		if _, ok, _ := p.Decide(c.conn); ok != c.want {
			t.Errorf("%s: allowed = %v", c.name, ok)
		}
	}
}

// Anything that could never match is an error, so a typo cannot pass for a
// rule that simply saw no traffic.
func TestPolicyRejects(t *testing.T) {
	rule := func(r string) string {
		return `{"zones":[{"name":"z","devices":["any"]}],"rules":[` + r + `]}`
	}
	for name, doc := range map[string]string{
		"unknown field":   `{"rule":[]}`,
		"unknown zone":    rule(`{"from":"zone:nope","to":"any","action":"deny"}`),
		"unknown kind":    rule(`{"from":"any","to":"host:x","action":"deny"}`),
		"bad prefix":      rule(`{"from":"any","to":"ip:10.0.0.0/99","action":"deny"}`),
		"bad address":     rule(`{"from":"any","to":"ip:nope","action":"deny"}`),
		"bad asn":         rule(`{"from":"any","to":"asn:cloud","action":"deny"}`),
		"bad port":        rule(`{"from":"any","to":"any","ports":["https"],"action":"deny"}`),
		"port range":      rule(`{"from":"any","to":"any","ports":["70000"],"action":"deny"}`),
		"bad glob":        rule(`{"from":"any","to":"domain:[","action":"deny"}`),
		"bad action":      rule(`{"from":"any","to":"any","action":"maybe"}`),
		"ssid selector":   `{"zones":[{"name":"z","devices":["ssid:cafe"]}]}`,
		"bad dns pattern": `{"dns":{"block":["["]}}`,
		"too many rules":  rule(strings.TrimSuffix(strings.Repeat(`{"from":"any","to":"any","action":"deny"},`, maxRules+1), ",")),
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, sel := range []string{"any", "*", "zone:any", "zone:z", "site:*.example.com", "domain:a.example", "ip:10.0.0.1", "ip:2001:db8::/32", "asn:AS13335", "country:DE", "printer*", "2001:db8::1"} {
		if _, err := Parse(strings.NewReader(rule(`{"from":"any","to":"` + sel + `","action":"deny"}`))); err != nil {
			t.Errorf("%s: %v", sel, err)
		}
	}
}
