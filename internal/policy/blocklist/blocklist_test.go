package blocklist

import (
	"strings"
	"testing"
)

func TestParseHostsAndMatcher(t *testing.T) {
	doc := `# Title: test list
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
fe80::1%lo0 localhost
255.255.255.255 broadcasthost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example
127.0.0.1 tracker.example # inline
::1 v6.example
1.2.3.0/24
10.0.0.1-10.0.0.9
2001:db8:1::/48
`
	p, err := Parse(strings.NewReader(doc), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if p.Title != "test list" {
		t.Fatalf("title = %q", p.Title)
	}
	m := New(p.Entries)
	// A hosts file blocks exactly the names it lists.
	if e, ok := m.MatchName("ads.example"); !ok || e.Value != "ads.example" || e.Kind != "host" {
		t.Fatalf("host match = %+v %v", e, ok)
	}
	if _, ok := m.MatchName("x.ads.example"); ok {
		t.Fatal("a hosts entry covered a subdomain")
	}
	// The address a hosts file sends names to isn't blocked, nor is localhost.
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "::1", "255.255.255.255"} {
		if _, ok := m.MatchIP(ip); ok {
			t.Fatalf("sinkhole %s became a block", ip)
		}
	}
	if _, ok := m.MatchName("localhost"); ok {
		t.Fatal("localhost blocked")
	}
	if e, ok := m.MatchIP("2001:db8:1:ffff::1"); !ok || e.Value != "2001:db8:1::/48" {
		t.Fatalf("v6 prefix match = %+v %v", e, ok)
	}
	if _, ok := m.MatchIP("2001:db8:2::1"); ok {
		t.Fatal("v6 prefix over-matched")
	}
	if e, ok := m.MatchName("tracker.example"); !ok || e.Value != "tracker.example" {
		t.Fatalf("exact match = %+v %v", e, ok)
	}
	if _, ok := m.MatchName("notads.example"); ok {
		t.Fatal("false domain match")
	}
	if e, ok := m.MatchIP("1.2.3.9"); !ok || e.Value != "1.2.3.0/24" {
		t.Fatalf("ip match = %+v %v", e, ok)
	}
	if e, ok := m.MatchIP("10.0.0.5"); !ok || e.Value != "10.0.0.1-10.0.0.9" {
		t.Fatalf("range match = %+v %v", e, ok)
	}
	if _, ok := m.MatchIP("10.0.0.10"); ok {
		t.Fatal("range over-matched")
	}
}

func TestParseLSRules(t *testing.T) {
	doc := `{"title":"r","rules":[
	  {"action":"deny","remote":{"type":"domain","values":["*.ads.example"]}},
	  {"action":"allow","remote":{"type":"domain","values":["ok.example"]}},
	  {"action":"deny","denied-remote-hosts":["bad.example"]},
	  {"action":"deny","process":"any","remote-domains":"lsdomain.example"},
	  {"action":"deny","process":"any","remote-hosts":["lshost.example"]},
	  {"action":"deny","process":"any","remote":"any"},
	  {"process":"any","remote-domains":"unlabelled.example"}
	],"denied-remote-addresses":["203.0.113.0/24"]}`
	p, err := Parse(strings.NewReader(doc), FormatLSRules)
	if err != nil {
		t.Fatal(err)
	}
	m := New(p.Entries)
	if _, ok := m.MatchName("x.ads.example"); !ok {
		t.Fatal("lsrules domain not matched")
	}
	if _, ok := m.MatchName("ok.example"); ok {
		t.Fatal("allow rule became a block")
	}
	if _, ok := m.MatchIP("203.0.113.9"); !ok {
		t.Fatal("lsrules address not matched")
	}
	if _, ok := m.MatchName("a.lsdomain.example"); !ok {
		t.Fatal("remote-domains not read")
	}
	if _, ok := m.MatchName("lshost.example"); !ok {
		t.Fatal("remote-hosts not read")
	}
	for _, name := range []string{"any", "unlabelled.example"} {
		if _, ok := m.MatchName(name); ok {
			t.Fatalf("%s became a block", name)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("0.0.0.0 ads.example\n1.2.3.0/24\n"), "auto")
	f.Add([]byte(`{"rules":[{"action":"deny","remote-domains":["x.example"]}]}`), "lsrules")
	f.Add([]byte("10.0.0.1-10.0.0.9\n::/0\n"), "ips")
	f.Fuzz(func(t *testing.T, b []byte, format string) {
		p, err := Parse(strings.NewReader(string(b)), format)
		if err != nil {
			return
		}
		if len(p.Entries) > maxEntries {
			t.Fatalf("%d entries", len(p.Entries))
		}
		m := New(p.Entries)
		for _, e := range p.Entries {
			switch e.Kind {
			case "ip":
				lo, _, _ := strings.Cut(e.Value, "-")
				lo, _, _ = strings.Cut(lo, "/")
				if _, ok := m.MatchIP(lo); !ok {
					t.Fatalf("entry %+v does not match its own address", e)
				}
			default:
				if _, ok := m.MatchName(e.Value); !ok {
					t.Fatalf("entry %+v does not match itself", e)
				}
			}
		}
	})
}

func TestParseRejectsEmptyAndBounds(t *testing.T) {
	if _, err := Parse(strings.NewReader("# only comments\n"), FormatHosts); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := Parse(strings.NewReader("x\n"), "nope"); err == nil {
		t.Fatal("bad format accepted")
	}
}
