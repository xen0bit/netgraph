package policy

import (
	"bytes"
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
	if rule, ok, matched := p.Decide("iot", "out", "api.vendor.example", "1.2.3.4", "443", "tcp", 0, ""); !ok || !matched || rule != "https" {
		t.Fatalf("https decision = %q %v %v", rule, ok, matched)
	}
	if _, ok, _ := p.Decide("iot", "out", "api.vendor.example", "1.2.3.4", "80", "tcp", 0, ""); ok {
		t.Fatal("port 80 was allowed")
	}
	if _, ok, _ := p.Decide("unknown", "out", "x", "1.2.3.4", "443", "tcp", 0, ""); ok {
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
