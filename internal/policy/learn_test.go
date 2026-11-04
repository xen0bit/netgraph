package policy

import (
	"strings"
	"testing"
)

func TestLearnWritesWhatWasSeen(t *testing.T) {
	seen := []Seen{
		{Direction: "out", Name: "api.example.com", IP: "93.184.216.34", Port: "443", Proto: "tcp", Bytes: 900},
		{Direction: "out", Name: "cdn.example.com", IP: "93.184.216.35", Port: "443", Proto: "tcp", Bytes: 100},
		{Direction: "out", Name: "", IP: "192.0.2.53", Port: "53", Proto: "udp", Bytes: 50},
		{Direction: "out", Name: "192.0.2.8", IP: "192.0.2.8", Port: "123", Proto: "udp", Bytes: 10},
		{Direction: "local", Name: "nas.lan", IP: "192.168.1.5", Port: "445", Proto: "tcp", Bytes: 5000},
		{Direction: "in", Name: "", IP: "203.0.113.9", Port: "8080", Proto: "tcp", Bytes: 3},
		{Direction: "in", Name: "", IP: "203.0.113.10", Port: "8080", Proto: "tcp", Bytes: 3},
		{Direction: "external", IP: "1.1.1.1", Port: "80", Proto: "tcp"},
		{Direction: "out", IP: "not-an-address", Port: "80", Proto: "tcp"},
		{Direction: "out", IP: "192.0.2.1", Proto: "icmp"},
	}
	p, gaps := Learn("device:aa:bb:cc:00:00:01", seen)
	if len(gaps) != 0 {
		t.Errorf("%v", gaps)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Defaults.Egress != "deny" || p.Defaults.Ingress != "deny" {
		t.Errorf("%+v", p.Defaults)
	}
	got := map[string]bool{}
	for _, r := range p.Rules {
		got[r.From+" "+r.To+" "+strings.Join(r.Ports, ",")] = true
	}
	for _, want := range []string{
		"zone:this site:example.com 443/tcp",
		"zone:this ip:192.0.2.53 53/udp",
		"zone:this ip:192.0.2.8 123/udp",
		"any zone:this 8080/tcp",
	} {
		if !got[want] {
			t.Errorf("no %q in %v", want, got)
		}
	}
	// It lets through everything it learned from, and not much else.
	allowed := func(c Conn) bool { _, ok, _ := p.Decide(c); return ok }
	for _, s := range seen {
		if s.Direction == "external" || s.IP == "not-an-address" {
			continue
		}
		c := Conn{Zone: "this", Direction: s.Direction, Name: s.Name, IP: s.IP, Port: s.Port, Proto: s.Proto}
		if s.Name == "" {
			c.Name = s.IP
		}
		if c.Port == "" {
			c.Port = "0"
		}
		if !allowed(c) {
			t.Errorf("it blocks what it learned from: %+v", s)
		}
	}
	if allowed(Conn{Zone: "this", Direction: "out", Name: "evil.test", IP: "198.51.100.1", Port: "443", Proto: "tcp"}) {
		t.Error("allowed something never seen")
	}
	if allowed(Conn{Zone: "this", Direction: "out", Name: "api.example.com", IP: "93.184.216.34", Port: "22", Proto: "tcp"}) {
		t.Error("allowed another port on a known site")
	}
}

func TestLearnIsDeterministicAndBounded(t *testing.T) {
	var seen []Seen
	for i := range 300 {
		seen = append(seen, Seen{Direction: "out", IP: "10.0." + itoa(i%10) + "." + itoa(i/10), Port: "443", Proto: "tcp", Bytes: uint64(i)})
	}
	a, gaps := Learn("device:aa:bb:cc:00:00:01", seen)
	if len(a.Rules) != MaxLearnedRules || len(gaps) != 1 {
		t.Errorf("%d rules, gaps %v", len(a.Rules), gaps)
	}
	b, _ := Learn("device:aa:bb:cc:00:00:01", seen)
	if a.Hash() != b.Hash() {
		t.Error("the same traffic gave a different policy")
	}
}
